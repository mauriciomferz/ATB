import { useState } from 'react';
import { verifyPoa, type PoaVerificationResult } from '../api';

interface DecodedToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export default function TokenInspector() {
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState<DecodedToken | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [verificationResult, setVerificationResult] = useState<PoaVerificationResult | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [testAction, setTestAction] = useState('');

  const decodeToken = () => {
    setError(null);
    setDecoded(null);
    setVerificationResult(null);

    if (!token.trim()) {
      setError('Please enter a token');
      return;
    }

    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        setError('Invalid JWT format: expected 3 parts separated by dots');
        return;
      }

      const decodeBase64 = (str: string) => {
        // Handle URL-safe base64
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
        return JSON.parse(atob(padded));
      };

      const header = decodeBase64(parts[0]);
      const payload = decodeBase64(parts[1]);

      setDecoded({
        header,
        payload,
        signature: parts[2],
      });

      // Auto-populate action from token if present
      if (payload.act && typeof payload.act === 'string') {
        setTestAction(payload.act);
      }
    } catch (e) {
      setError(`Failed to decode token: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const verifyToken = async () => {
    if (!token.trim()) {
      setError('Please enter a token');
      return;
    }

    setIsVerifying(true);
    setError(null);

    try {
      const result = await verifyPoa(token, testAction || undefined);
      setVerificationResult(result);
    } catch (e) {
      setError(`Verification failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    } finally {
      setIsVerifying(false);
    }
  };

  const formatTimestamp = (ts: number) => {
    return new Date(ts * 1000).toLocaleString();
  };

  const isExpired = decoded?.payload.exp && (decoded.payload.exp as number) < Date.now() / 1000;

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">PoA Token Inspector</h1>

      {/* Token Input */}
      <div className="card">
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
          Paste JWT Token
        </label>
        <textarea
          className="w-full h-32 px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-primary-500 focus:border-transparent"
          placeholder="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
          value={token}
          onChange={(e) => setToken(e.target.value)}
        />
        <div className="mt-4 flex gap-4">
          <button className="btn btn-primary" onClick={decodeToken}>
            Decode Token
          </button>
          <button 
            className="btn bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50"
            onClick={verifyToken}
            disabled={isVerifying || !token.trim()}
          >
            {isVerifying ? 'Verifying...' : '🔐 Verify Signature'}
          </button>
          <button
            className="btn bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600"
            onClick={() => {
              setToken('');
              setDecoded(null);
              setError(null);
              setVerificationResult(null);
              setTestAction('');
            }}
          >
            Clear
          </button>
        </div>

        {/* Action to test against */}
        <div className="mt-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Test Action (optional)
          </label>
          <input
            type="text"
            className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg font-mono text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
            placeholder="e.g., sap.vendor.bank_change"
            value={testAction}
            onChange={(e) => setTestAction(e.target.value)}
          />
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
            Specify an action to test policy evaluation against
          </p>
        </div>
      </div>

      {/* Verification Result */}
      {verificationResult && (
        <VerificationResultPanel result={verificationResult} />
      )}

      {/* Error */}
      {error && (
        <div className="p-4 bg-danger-50 dark:bg-danger-900/20 border border-danger-200 dark:border-danger-800 rounded-lg">
          <p className="text-danger-600 dark:text-danger-400">{error}</p>
        </div>
      )}

      {/* Decoded Token */}
      {decoded && (
        <div className="space-y-6">
          {/* Status Banner */}
          <div
            className={`p-4 rounded-lg border ${
              isExpired
                ? 'bg-danger-50 dark:bg-danger-900/20 border-danger-200 dark:border-danger-800'
                : 'bg-success-50 dark:bg-success-900/20 border-success-200 dark:border-success-800'
            }`}
          >
            <div className="flex items-center gap-2">
              <span
                className={`w-3 h-3 rounded-full ${isExpired ? 'bg-danger-500' : 'bg-success-500'}`}
              />
              <span className={isExpired ? 'text-danger-700 dark:text-danger-400' : 'text-success-700 dark:text-success-400'}>
                {isExpired ? 'Token Expired' : 'Token Valid (not expired)'}
              </span>
            </div>
          </div>

          {/* Header */}
          <div className="card">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Header</h3>
            <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto text-sm">
              <code className="text-gray-800 dark:text-gray-200">
                {JSON.stringify(decoded.header, null, 2)}
              </code>
            </pre>
          </div>

          {/* Payload */}
          <div className="card">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Payload (Claims)</h3>
            
            {/* Key Fields */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              {'sub' in decoded.payload && decoded.payload.sub != null && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Subject (Agent)</dt>
                  <dd className="font-mono text-sm text-gray-900 dark:text-gray-100 break-all">
                    {String(decoded.payload.sub)}
                  </dd>
                </div>
              )}
              {'act' in decoded.payload && decoded.payload.act != null && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Action</dt>
                  <dd className="font-mono text-sm text-gray-900 dark:text-gray-100">
                    {String(decoded.payload.act)}
                  </dd>
                </div>
              )}
              {'iat' in decoded.payload && decoded.payload.iat != null && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Issued At</dt>
                  <dd className="text-sm text-gray-900 dark:text-gray-100">
                    {formatTimestamp(decoded.payload.iat as number)}
                  </dd>
                </div>
              )}
              {'exp' in decoded.payload && decoded.payload.exp != null && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Expires At</dt>
                  <dd className={`text-sm ${isExpired ? 'text-danger-600' : 'text-gray-900 dark:text-gray-100'}`}>
                    {formatTimestamp(decoded.payload.exp as number)}
                  </dd>
                </div>
              )}
              {'jti' in decoded.payload && decoded.payload.jti != null && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Token ID (jti)</dt>
                  <dd className="font-mono text-sm text-gray-900 dark:text-gray-100">
                    {String(decoded.payload.jti)}
                  </dd>
                </div>
              )}
            </div>

            {/* Legal Grounding */}
            {'leg' in decoded.payload && decoded.payload.leg != null && (
              <div className="mb-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Legal Grounding
                </h4>
                <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto text-sm">
                  <code className="text-gray-800 dark:text-gray-200">
                    {JSON.stringify(decoded.payload.leg, null, 2)}
                  </code>
                </pre>
              </div>
            )}

            {/* Constraints */}
            {'con' in decoded.payload && decoded.payload.con != null && (
              <div className="mb-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Constraints
                </h4>
                <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto text-sm">
                  <code className="text-gray-800 dark:text-gray-200">
                    {JSON.stringify(decoded.payload.con, null, 2)}
                  </code>
                </pre>
              </div>
            )}

            {/* Full Payload */}
            <details className="mt-4">
              <summary className="cursor-pointer text-sm text-primary-600 dark:text-primary-400 hover:underline">
                View Full Payload
              </summary>
              <pre className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg overflow-x-auto text-sm mt-2">
                <code className="text-gray-800 dark:text-gray-200">
                  {JSON.stringify(decoded.payload, null, 2)}
                </code>
              </pre>
            </details>
          </div>

          {/* Signature */}
          <div className="card">
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Signature</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400 mb-2">
              Base64-encoded signature (verification requires public key)
            </p>
            <code className="block bg-gray-100 dark:bg-gray-800 p-4 rounded-lg text-sm font-mono text-gray-800 dark:text-gray-200 break-all">
              {decoded.signature}
            </code>
          </div>
        </div>
      )}
    </div>
  );
}

function VerificationResultPanel({ result }: { result: PoaVerificationResult }) {
  const riskTierColors = {
    LOW: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
    MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
    HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
    CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
  };

  return (
    <div className="card">
      <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
        🔐 Verification Result
      </h3>

      {/* Overall Status */}
      <div
        className={`p-4 rounded-lg mb-6 ${
          result.valid
            ? 'bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800'
            : 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'
        }`}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span
              className={`w-4 h-4 rounded-full ${result.valid ? 'bg-green-500' : 'bg-red-500'}`}
            />
            <span
              className={`text-lg font-semibold ${
                result.valid
                  ? 'text-green-700 dark:text-green-400'
                  : 'text-red-700 dark:text-red-400'
              }`}
            >
              {result.valid ? '✓ Valid POA Token' : '✗ Invalid POA Token'}
            </span>
          </div>
          <span className={`px-2 py-1 rounded text-sm font-medium ${riskTierColors[result.riskTier]}`}>
            {result.riskTier} RISK
          </span>
        </div>

        {result.policyEvaluation && (
          <div className="mt-3 pt-3 border-t border-green-200 dark:border-green-800">
            <span className="text-sm text-gray-600 dark:text-gray-400">Policy Decision: </span>
            <span
              className={`font-medium ${
                result.policyEvaluation.decision === 'allow'
                  ? 'text-green-600 dark:text-green-400'
                  : 'text-red-600 dark:text-red-400'
              }`}
            >
              {result.policyEvaluation.decision.toUpperCase()}
            </span>
            {result.policyEvaluation.reason && (
              <span className="text-sm text-gray-500 dark:text-gray-400">
                {' '}
                — {result.policyEvaluation.reason}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Status Badges */}
      <div className="flex flex-wrap gap-2 mb-6">
        <StatusBadge
          label="Signature"
          passed={result.signatureValid}
          passedText="Valid"
          failedText="Invalid"
        />
        <StatusBadge
          label="Expiration"
          passed={!result.expired}
          passedText="Not Expired"
          failedText="Expired"
        />
        <StatusBadge
          label="Revocation"
          passed={!result.revoked}
          passedText="Active"
          failedText="Revoked"
        />
      </div>

      {/* Detailed Checks */}
      <div>
        <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
          Verification Checks
        </h4>
        <div className="space-y-2">
          {result.checks.map((check, i) => (
            <div
              key={i}
              className={`flex items-start gap-3 p-3 rounded-lg ${
                check.passed
                  ? 'bg-green-50 dark:bg-green-900/10'
                  : 'bg-red-50 dark:bg-red-900/10'
              }`}
            >
              <span className="text-lg">{check.passed ? '✓' : '✗'}</span>
              <div>
                <span
                  className={`font-medium ${
                    check.passed
                      ? 'text-green-700 dark:text-green-400'
                      : 'text-red-700 dark:text-red-400'
                  }`}
                >
                  {check.name}
                </span>
                <p className="text-sm text-gray-600 dark:text-gray-400">{check.message}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Time Policy Violations */}
      {result.policyEvaluation?.timePolicyViolations &&
        result.policyEvaluation.timePolicyViolations.length > 0 && (
          <div className="mt-6">
            <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
              ⏰ Time Policy Violations
            </h4>
            <div className="flex flex-wrap gap-2">
              {result.policyEvaluation.timePolicyViolations.map((violation, i) => (
                <span
                  key={i}
                  className="px-2 py-1 rounded bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300 text-sm"
                >
                  {violation.replace(/_/g, ' ')}
                </span>
              ))}
            </div>
          </div>
        )}
    </div>
  );
}

function StatusBadge({
  label,
  passed,
  passedText,
  failedText,
}: {
  label: string;
  passed: boolean;
  passedText: string;
  failedText: string;
}) {
  return (
    <div
      className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm ${
        passed
          ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300'
          : 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300'
      }`}
    >
      <span>{passed ? '✓' : '✗'}</span>
      <span className="font-medium">{label}:</span>
      <span>{passed ? passedText : failedText}</span>
    </div>
  );
}

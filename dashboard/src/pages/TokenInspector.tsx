import { useState } from 'react';

interface DecodedToken {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export default function TokenInspector() {
  const [token, setToken] = useState('');
  const [decoded, setDecoded] = useState<DecodedToken | null>(null);
  const [error, setError] = useState<string | null>(null);

  const decodeToken = () => {
    setError(null);
    setDecoded(null);

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
    } catch (e) {
      setError(`Failed to decode token: ${e instanceof Error ? e.message : 'Unknown error'}`);
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
            className="btn bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600"
            onClick={() => {
              setToken('');
              setDecoded(null);
              setError(null);
            }}
          >
            Clear
          </button>
        </div>
      </div>

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
              {decoded.payload.sub && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Subject (Agent)</dt>
                  <dd className="font-mono text-sm text-gray-900 dark:text-gray-100 break-all">
                    {decoded.payload.sub as string}
                  </dd>
                </div>
              )}
              {decoded.payload.act && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Action</dt>
                  <dd className="font-mono text-sm text-gray-900 dark:text-gray-100">
                    {decoded.payload.act as string}
                  </dd>
                </div>
              )}
              {decoded.payload.iat && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Issued At</dt>
                  <dd className="text-sm text-gray-900 dark:text-gray-100">
                    {formatTimestamp(decoded.payload.iat as number)}
                  </dd>
                </div>
              )}
              {decoded.payload.exp && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Expires At</dt>
                  <dd className={`text-sm ${isExpired ? 'text-danger-600' : 'text-gray-900 dark:text-gray-100'}`}>
                    {formatTimestamp(decoded.payload.exp as number)}
                  </dd>
                </div>
              )}
              {decoded.payload.jti && (
                <div>
                  <dt className="text-sm text-gray-500 dark:text-gray-400">Token ID (jti)</dt>
                  <dd className="font-mono text-sm text-gray-900 dark:text-gray-100">
                    {decoded.payload.jti as string}
                  </dd>
                </div>
              )}
            </div>

            {/* Legal Grounding */}
            {decoded.payload.leg && (
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
            {decoded.payload.con && (
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

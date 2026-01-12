import { useQuery } from '@tanstack/react-query';
import { fetchPolicyStats } from '../api';

export default function Policies() {
  const { data: policies, isLoading } = useQuery({
    queryKey: ['policies', 'stats'],
    queryFn: fetchPolicyStats,
  });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Policy Statistics</h1>

      {isLoading ? (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading...</div>
      ) : (
        <div className="grid gap-6">
          {policies?.map((policy) => (
            <div key={policy.name} className="card">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-medium font-mono text-gray-900 dark:text-white">{policy.name}</h3>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                    {policy.evaluations.toLocaleString()} evaluations
                  </p>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-success-600 dark:text-success-400">
                    {(policy.allowRate * 100).toFixed(1)}%
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">allow rate</div>
                </div>
              </div>

              <div className="mt-4">
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-500 dark:text-gray-400">Allow/Deny Distribution</span>
                  <span className="text-gray-700 dark:text-gray-300">{policy.avgLatencyMs}ms avg</span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <div
                    className="bg-success-500 h-2 rounded-full"
                    style={{ width: `${policy.allowRate * 100}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Policy Documentation */}
      <div className="card">
        <h3 className="text-lg font-medium mb-4 dark:text-white">Policy Overview</h3>
        <div className="prose prose-sm max-w-none dark:prose-invert">
          <p className="text-gray-600 dark:text-gray-400">
            ATB uses Open Policy Agent (OPA) for policy enforcement. The main policies are:
          </p>
          <ul className="mt-4 space-y-2">
            <li className="flex items-start">
              <span className="font-mono text-primary-600 dark:text-primary-400 mr-2">poa/allow</span>
              <span className="text-gray-600 dark:text-gray-400">Main decision rule - evaluates all PoA claims</span>
            </li>
            <li className="flex items-start">
              <span className="font-mono text-primary-600 dark:text-primary-400 mr-2">poa/risk_tier</span>
              <span className="text-gray-600 dark:text-gray-400">Determines risk classification (LOW/MEDIUM/HIGH)</span>
            </li>
            <li className="flex items-start">
              <span className="font-mono text-primary-600 dark:text-primary-400 mr-2">poa/leg_valid</span>
              <span className="text-gray-600 dark:text-gray-400">Validates legal grounding claims</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}

import { useQuery } from '@tanstack/react-query';
import { fetchAgents } from '../api';
import { format, formatDistanceToNow } from 'date-fns';

export default function Agents() {
  const { data: agents, isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: fetchAgents,
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Registered Agents</h1>
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {agents?.length || 0} active agents
        </span>
      </div>

      {isLoading ? (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading...</div>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {agents?.map((agent) => (
            <AgentCard key={agent.spiffeId} agent={agent} />
          ))}
        </div>
      )}

      {/* Agent Legend */}
      <div className="card">
        <h3 className="text-lg font-medium mb-4 dark:text-white">Risk Profiles</h3>
        <div className="grid grid-cols-3 gap-4">
          <div className="flex items-center">
            <span className="w-3 h-3 rounded-full bg-success-500 mr-2"></span>
            <span className="text-sm text-gray-600 dark:text-gray-400">LOW - Read-only, non-sensitive</span>
          </div>
          <div className="flex items-center">
            <span className="w-3 h-3 rounded-full bg-warning-500 mr-2"></span>
            <span className="text-sm text-gray-600 dark:text-gray-400">MEDIUM - Writes, bulk operations</span>
          </div>
          <div className="flex items-center">
            <span className="w-3 h-3 rounded-full bg-danger-500 mr-2"></span>
            <span className="text-sm text-gray-600 dark:text-gray-400">HIGH - Financial, admin actions</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function AgentCard({ agent }: { agent: { spiffeId: string; lastSeen: string; requestCount: number; allowRate: number; riskProfile: string } }) {
  const riskColors = {
    LOW: 'bg-success-500',
    MEDIUM: 'bg-warning-500',
    HIGH: 'bg-danger-500',
  };

  const agentName = agent.spiffeId.split('/').pop() || agent.spiffeId;
  const trustDomain = agent.spiffeId.replace('spiffe://', '').split('/')[0];

  return (
    <div className="card">
      <div className="flex items-start justify-between">
        <div className="flex items-center">
          <span className={`w-3 h-3 rounded-full mr-3 ${riskColors[agent.riskProfile as keyof typeof riskColors]}`}></span>
          <div>
            <h3 className="font-medium text-gray-900 dark:text-white">{agentName}</h3>
            <p className="text-xs text-gray-500 dark:text-gray-400">{trustDomain}</p>
          </div>
        </div>
        <span className={`badge ${agent.riskProfile === 'LOW' ? 'badge-success' : agent.riskProfile === 'MEDIUM' ? 'badge-warning' : 'badge-danger'}`}>
          {agent.riskProfile}
        </span>
      </div>

      <dl className="mt-4 space-y-2">
        <div className="flex justify-between text-sm">
          <dt className="text-gray-500 dark:text-gray-400">Last seen</dt>
          <dd className="text-gray-900 dark:text-white">
            {formatDistanceToNow(new Date(agent.lastSeen), { addSuffix: true })}
          </dd>
        </div>
        <div className="flex justify-between text-sm">
          <dt className="text-gray-500 dark:text-gray-400">Total requests</dt>
          <dd className="text-gray-900 dark:text-white font-medium">{agent.requestCount.toLocaleString()}</dd>
        </div>
        <div className="flex justify-between text-sm">
          <dt className="text-gray-500 dark:text-gray-400">Allow rate</dt>
          <dd className={`font-medium ${agent.allowRate >= 0.95 ? 'text-success-600 dark:text-success-400' : agent.allowRate >= 0.9 ? 'text-warning-600 dark:text-warning-400' : 'text-danger-600 dark:text-danger-400'}`}>
            {(agent.allowRate * 100).toFixed(1)}%
          </dd>
        </div>
      </dl>

      <div className="mt-4 pt-4 border-t dark:border-gray-700">
        <code className="text-xs text-gray-500 dark:text-gray-400 break-all">{agent.spiffeId}</code>
      </div>
    </div>
  );
}

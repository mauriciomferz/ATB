import { useQuery } from '@tanstack/react-query';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { fetchMetrics, fetchSystemHealth, fetchAuditEvents, fetchRequestsTimeSeries } from '../api';
import { format } from 'date-fns';
import RiskDistributionChart from '../components/RiskDistributionChart';

export default function Dashboard() {
  const { data: metrics } = useQuery({ queryKey: ['metrics'], queryFn: fetchMetrics });
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: fetchSystemHealth });
  const { data: recentEvents } = useQuery({ queryKey: ['audit', 'recent'], queryFn: () => fetchAuditEvents(5) });
  const { data: timeSeries } = useQuery({ queryKey: ['requests', 'timeseries'], queryFn: fetchRequestsTimeSeries });
  const { data: allEvents } = useQuery({ queryKey: ['audit', 'all'], queryFn: () => fetchAuditEvents(100) });

  // Calculate risk distribution from events
  const riskDistribution = allEvents?.reduce(
    (acc, event) => {
      acc[event.riskTier]++;
      return acc;
    },
    { LOW: 0, MEDIUM: 0, HIGH: 0 }
  ) || { LOW: 0, MEDIUM: 0, HIGH: 0 };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Dashboard Overview</h1>

      {/* System Health */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <HealthCard
          title="Broker"
          status={health?.broker.status || 'unknown'}
          details={[
            { label: 'Version', value: health?.broker.version || '-' },
            { label: 'Uptime', value: health ? formatUptime(health.broker.uptime) : '-' },
          ]}
        />
        <HealthCard
          title="OPA"
          status={health?.opa.status || 'unknown'}
          details={[
            { label: 'Policies', value: health?.opa.policyCount?.toString() || '-' },
            { label: 'Last Sync', value: health?.opa.lastSync ? format(new Date(health.opa.lastSync), 'HH:mm:ss') : '-' },
          ]}
        />
        <HealthCard
          title="SPIRE"
          status={health?.spire.status || 'unknown'}
          details={[
            { label: 'Trust Domain', value: health?.spire.trustDomain || '-' },
            { label: 'Workloads', value: health?.spire.workloadCount?.toString() || '-' },
          ]}
        />
      </div>

      {/* Metrics Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard title="Total Requests" value={metrics?.totalRequests?.toLocaleString() || '0'} />
        <MetricCard title="Allow Rate" value={metrics ? `${((metrics.allowedRequests / metrics.totalRequests) * 100).toFixed(1)}%` : '0%'} color="text-success-600 dark:text-success-400" />
        <MetricCard title="Avg Latency" value={`${metrics?.avgLatencyMs || 0}ms`} />
        <MetricCard title="P95 Latency" value={`${metrics?.p95LatencyMs || 0}ms`} />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card lg:col-span-2">
          <h3 className="text-lg font-medium mb-4 dark:text-white">Requests (24h)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeries || []}>
                <CartesianGrid strokeDasharray="3 3" className="dark:opacity-30" />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(ts) => format(new Date(ts), 'HH:mm')}
                  className="dark:text-gray-300"
                />
                <YAxis className="dark:text-gray-300" />
                <Tooltip
                  labelFormatter={(ts) => format(new Date(ts as string), 'MMM d, HH:mm')}
                  contentStyle={{ backgroundColor: 'var(--tooltip-bg, #fff)', borderColor: 'var(--tooltip-border, #e5e7eb)' }}
                />
                <Line type="monotone" dataKey="allowed" stroke="#22c55e" name="Allowed" />
                <Line type="monotone" dataKey="denied" stroke="#ef4444" name="Denied" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk Distribution Pie Chart */}
        <div className="card">
          <h3 className="text-lg font-medium mb-4 dark:text-white">Risk Distribution</h3>
          <RiskDistributionChart data={riskDistribution} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-medium mb-4 dark:text-white">Decisions by Hour</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timeSeries?.slice(-12) || []}>
                <CartesianGrid strokeDasharray="3 3" className="dark:opacity-30" />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(ts) => format(new Date(ts), 'HH:mm')}
                />
                <YAxis />
                <Tooltip
                  labelFormatter={(ts) => format(new Date(ts as string), 'MMM d, HH:mm')}
                  contentStyle={{ backgroundColor: 'var(--tooltip-bg, #fff)', borderColor: 'var(--tooltip-border, #e5e7eb)' }}
                />
                <Bar dataKey="allowed" fill="#22c55e" name="Allowed" stackId="a" />
                <Bar dataKey="denied" fill="#ef4444" name="Denied" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Quick Stats Card */}
        <div className="card">
          <h3 className="text-lg font-medium mb-4 dark:text-white">Authorization Summary</h3>
          <div className="space-y-4">
            <div className="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
              <span className="text-gray-600 dark:text-gray-300">Total Events Today</span>
              <span className="text-xl font-bold text-gray-900 dark:text-white">{allEvents?.length || 0}</span>
            </div>
            <div className="flex justify-between items-center p-3 bg-green-50 dark:bg-green-900/30 rounded-lg">
              <span className="text-green-700 dark:text-green-300">Low Risk Actions</span>
              <span className="text-xl font-bold text-green-600 dark:text-green-400">{riskDistribution.LOW}</span>
            </div>
            <div className="flex justify-between items-center p-3 bg-yellow-50 dark:bg-yellow-900/30 rounded-lg">
              <span className="text-yellow-700 dark:text-yellow-300">Medium Risk Actions</span>
              <span className="text-xl font-bold text-yellow-600 dark:text-yellow-400">{riskDistribution.MEDIUM}</span>
            </div>
            <div className="flex justify-between items-center p-3 bg-red-50 dark:bg-red-900/30 rounded-lg">
              <span className="text-red-700 dark:text-red-300">High Risk Actions</span>
              <span className="text-xl font-bold text-red-600 dark:text-red-400">{riskDistribution.HIGH}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Events */}
      <div className="card">
        <h3 className="text-lg font-medium mb-4 dark:text-white">Recent Authorization Events</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead>
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Time</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Action</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Agent</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Decision</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {recentEvents?.map((event) => (
                <tr key={event.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">
                    {format(new Date(event.timestamp), 'HH:mm:ss')}
                  </td>
                  <td className="px-4 py-2 text-sm font-mono text-gray-900 dark:text-white">{event.action}</td>
                  <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400 truncate max-w-xs">{event.agent.split('/').pop()}</td>
                  <td className="px-4 py-2">
                    <span className={`badge ${event.decision === 'allow' ? 'badge-success' : 'badge-danger'}`}>
                      {event.decision}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-sm text-gray-600 dark:text-gray-400">{event.durationMs}ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function HealthCard({
  title,
  status,
  details,
}: {
  title: string;
  status: string;
  details: Array<{ label: string; value: string }>;
}) {
  const statusColors = {
    healthy: 'bg-success-500',
    degraded: 'bg-warning-500',
    unhealthy: 'bg-danger-500',
    unknown: 'bg-gray-400',
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-medium">{title}</h3>
        <span className={`w-3 h-3 rounded-full ${statusColors[status as keyof typeof statusColors] || statusColors.unknown}`} />
      </div>
      <dl className="space-y-2">
        {details.map(({ label, value }) => (
          <div key={label} className="flex justify-between text-sm">
            <dt className="text-gray-500">{label}</dt>
            <dd className="text-gray-900 font-medium">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function MetricCard({ title, value, color = 'text-gray-900' }: { title: string; value: string; color?: string }) {
  return (
    <div className="card">
      <dt className="text-sm text-gray-500 truncate">{title}</dt>
      <dd className={`text-2xl font-bold ${color}`}>{value}</dd>
    </div>
  );
}

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  return `${hours}h`;
}

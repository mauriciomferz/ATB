import { useQuery } from '@tanstack/react-query';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { fetchMetrics, fetchSystemHealth, fetchAuditEvents, fetchRequestsTimeSeries } from '../api';
import { format } from 'date-fns';

export default function Dashboard() {
  const { data: metrics } = useQuery({ queryKey: ['metrics'], queryFn: fetchMetrics });
  const { data: health } = useQuery({ queryKey: ['health'], queryFn: fetchSystemHealth });
  const { data: recentEvents } = useQuery({ queryKey: ['audit', 'recent'], queryFn: () => fetchAuditEvents(5) });
  const { data: timeSeries } = useQuery({ queryKey: ['requests', 'timeseries'], queryFn: fetchRequestsTimeSeries });

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900">Dashboard Overview</h1>

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
        <MetricCard title="Allow Rate" value={metrics ? `${((metrics.allowedRequests / metrics.totalRequests) * 100).toFixed(1)}%` : '0%'} color="text-success-600" />
        <MetricCard title="Avg Latency" value={`${metrics?.avgLatencyMs || 0}ms`} />
        <MetricCard title="P95 Latency" value={`${metrics?.p95LatencyMs || 0}ms`} />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-lg font-medium mb-4">Requests (24h)</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeries || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(ts) => format(new Date(ts), 'HH:mm')}
                />
                <YAxis />
                <Tooltip
                  labelFormatter={(ts) => format(new Date(ts as string), 'MMM d, HH:mm')}
                />
                <Line type="monotone" dataKey="allowed" stroke="#22c55e" name="Allowed" />
                <Line type="monotone" dataKey="denied" stroke="#ef4444" name="Denied" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <h3 className="text-lg font-medium mb-4">Decisions by Hour</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={timeSeries?.slice(-12) || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="timestamp"
                  tickFormatter={(ts) => format(new Date(ts), 'HH:mm')}
                />
                <YAxis />
                <Tooltip
                  labelFormatter={(ts) => format(new Date(ts as string), 'MMM d, HH:mm')}
                />
                <Bar dataKey="allowed" fill="#22c55e" name="Allowed" stackId="a" />
                <Bar dataKey="denied" fill="#ef4444" name="Denied" stackId="a" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Events */}
      <div className="card">
        <h3 className="text-lg font-medium mb-4">Recent Authorization Events</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Agent</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Decision</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {recentEvents?.map((event) => (
                <tr key={event.id}>
                  <td className="px-4 py-2 text-sm text-gray-600">
                    {format(new Date(event.timestamp), 'HH:mm:ss')}
                  </td>
                  <td className="px-4 py-2 text-sm font-mono text-gray-900">{event.action}</td>
                  <td className="px-4 py-2 text-sm text-gray-600 truncate max-w-xs">{event.agent.split('/').pop()}</td>
                  <td className="px-4 py-2">
                    <span className={`badge ${event.decision === 'allow' ? 'badge-success' : 'badge-danger'}`}>
                      {event.decision}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-sm text-gray-600">{event.durationMs}ms</td>
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

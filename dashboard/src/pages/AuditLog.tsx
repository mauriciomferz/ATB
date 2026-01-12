import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { fetchAuditEvents } from '../api';
import { format } from 'date-fns';
import type { AuditEvent } from '../types';
import ExportButton from '../components/ExportButton';

export default function AuditLog() {
  const [filter, setFilter] = useState<'all' | 'allow' | 'deny'>('all');
  const [search, setSearch] = useState('');

  const { data: events, isLoading } = useQuery({
    queryKey: ['audit', 'full'],
    queryFn: () => fetchAuditEvents(100),
  });

  const filteredEvents = events?.filter((event) => {
    if (filter !== 'all' && event.decision !== filter) return false;
    if (search && !event.action.includes(search) && !event.agent.includes(search)) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Audit Log</h1>
        <ExportButton data={filteredEvents || []} filename="atb-audit-log" />
      </div>

      {/* Filters */}
      <div className="flex gap-4 items-center flex-wrap">
        <div className="flex rounded-md shadow-sm">
          <button
            className={`px-4 py-2 text-sm font-medium rounded-l-md border ${filter === 'all' ? 'bg-primary-50 dark:bg-primary-900/30 text-primary-600 dark:text-primary-400 border-primary-500' : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600'}`}
            onClick={() => setFilter('all')}
          >
            All
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium border-t border-b ${filter === 'allow' ? 'bg-success-50 dark:bg-success-900/30 text-success-600 dark:text-success-400 border-success-500' : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 border-gray-300 dark:border-gray-600'}`}
            onClick={() => setFilter('allow')}
          >
            Allowed
          </button>
          <button
            className={`px-4 py-2 text-sm font-medium rounded-r-md border ${filter === 'deny' ? 'bg-danger-50 text-danger-600 border-danger-500' : 'bg-white text-gray-700 border-gray-300'}`}
            onClick={() => setFilter('deny')}
          >
            Denied
          </button>
        </div>

        <input
          type="text"
          placeholder="Search action or agent..."
          className="px-4 py-2 border border-gray-300 rounded-md text-sm w-64"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Events Table */}
      <div className="card overflow-hidden">
        {isLoading ? (
          <div className="text-center py-8 text-gray-500">Loading...</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Timestamp</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Agent</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Decision</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Accountable</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Jurisdiction</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Latency</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredEvents?.map((event) => (
                  <EventRow key={event.id} event={event} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

function EventRow({ event }: { event: AuditEvent }) {
  const riskColors = {
    LOW: 'badge-success',
    MEDIUM: 'badge-warning',
    HIGH: 'badge-danger',
  };

  return (
    <tr className="hover:bg-gray-50">
      <td className="px-4 py-3 text-sm text-gray-600 whitespace-nowrap">
        {format(new Date(event.timestamp), 'MMM d, HH:mm:ss')}
      </td>
      <td className="px-4 py-3 text-sm font-mono text-gray-900">{event.action}</td>
      <td className="px-4 py-3 text-sm text-gray-600 truncate max-w-xs" title={event.agent}>
        {event.agent.split('/').pop()}
      </td>
      <td className="px-4 py-3">
        <span className={`badge ${event.decision === 'allow' ? 'badge-success' : 'badge-danger'}`}>
          {event.decision}
        </span>
        {event.reason && (
          <span className="ml-2 text-xs text-gray-500" title={event.reason}>
            ⓘ
          </span>
        )}
      </td>
      <td className="px-4 py-3">
        <span className={`badge ${riskColors[event.riskTier]}`}>{event.riskTier}</span>
      </td>
      <td className="px-4 py-3 text-sm text-gray-600">
        {event.accountableParty.displayName || event.accountableParty.id}
      </td>
      <td className="px-4 py-3 text-sm text-gray-600">{event.jurisdiction}</td>
      <td className="px-4 py-3 text-sm text-gray-600">{event.durationMs}ms</td>
    </tr>
  );
}

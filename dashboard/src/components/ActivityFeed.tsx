import { useState, useEffect, useMemo } from 'react';
import { format, formatDistanceToNow } from 'date-fns';

interface ActivityEvent {
  id: string;
  timestamp: string;
  action: string;
  agent: string;
  decision: 'allow' | 'deny';
  riskTier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  durationMs: number;
  reason?: string;
  jurisdiction?: string;
  timePolicyViolation?: 'rate_limit_exceeded' | 'outside_business_hours' | 'approval_expired';
}

interface ActivityFeedProps {
  events: ActivityEvent[];
  maxEvents?: number;
  showFilters?: boolean;
  onEventClick?: (event: ActivityEvent) => void;
  isLive?: boolean;
  onToggleLive?: () => void;
}

const RISK_TIER_COLORS = {
  LOW: 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
};

const DECISION_COLORS = {
  allow: 'bg-green-500',
  deny: 'bg-red-500',
};

const TIME_VIOLATION_LABELS = {
  rate_limit_exceeded: '⚡ Rate Limit',
  outside_business_hours: '🕐 After Hours',
  approval_expired: '⏰ Expired',
};

export default function ActivityFeed({
  events,
  maxEvents = 50,
  showFilters = true,
  onEventClick,
  isLive = true,
  onToggleLive,
}: ActivityFeedProps) {
  const [filter, setFilter] = useState<{
    decision: 'all' | 'allow' | 'deny';
    riskTier: 'all' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    search: string;
  }>({
    decision: 'all',
    riskTier: 'all',
    search: '',
  });

  const [highlightedIds, setHighlightedIds] = useState<Set<string>>(new Set());

  // Highlight new events briefly
  useEffect(() => {
    if (events.length > 0 && isLive) {
      const newEvent = events[0];
      setHighlightedIds(new Set([newEvent.id]));
      const timer = setTimeout(() => setHighlightedIds(new Set()), 1500);
      return () => clearTimeout(timer);
    }
  }, [events, isLive]);

  const filteredEvents = useMemo(() => {
    return events
      .filter((event) => {
        if (filter.decision !== 'all' && event.decision !== filter.decision) return false;
        if (filter.riskTier !== 'all' && event.riskTier !== filter.riskTier) return false;
        if (filter.search) {
          const searchLower = filter.search.toLowerCase();
          return (
            event.action.toLowerCase().includes(searchLower) ||
            event.agent.toLowerCase().includes(searchLower) ||
            (event.reason && event.reason.toLowerCase().includes(searchLower))
          );
        }
        return true;
      })
      .slice(0, maxEvents);
  }, [events, filter, maxEvents]);

  const stats = useMemo(() => {
    const total = events.length;
    const allowed = events.filter((e) => e.decision === 'allow').length;
    const denied = events.filter((e) => e.decision === 'deny').length;
    const critical = events.filter((e) => e.riskTier === 'CRITICAL').length;
    return { total, allowed, denied, critical };
  }, [events]);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b dark:border-gray-700">
        <div className="flex items-center gap-3">
          <h3 className="text-lg font-semibold dark:text-white">Activity Feed</h3>
          {isLive && (
            <span className="flex items-center gap-1.5">
              <span className="relative flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500"></span>
              </span>
              <span className="text-sm text-green-600 dark:text-green-400">Live</span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {onToggleLive && (
            <button
              onClick={onToggleLive}
              className={`px-3 py-1 text-sm rounded-md transition-colors ${
                isLive
                  ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-400'
                  : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
              }`}
            >
              {isLive ? '⏸ Pause' : '▶ Resume'}
            </button>
          )}
        </div>
      </div>

      {/* Stats Bar */}
      <div className="flex gap-4 p-3 bg-gray-50 dark:bg-gray-800/50 text-sm">
        <span className="text-gray-600 dark:text-gray-400">
          Total: <strong className="text-gray-900 dark:text-white">{stats.total}</strong>
        </span>
        <span className="text-green-600 dark:text-green-400">
          Allowed: <strong>{stats.allowed}</strong>
        </span>
        <span className="text-red-600 dark:text-red-400">
          Denied: <strong>{stats.denied}</strong>
        </span>
        {stats.critical > 0 && (
          <span className="text-red-700 dark:text-red-300 font-semibold">
            ⚠️ Critical: {stats.critical}
          </span>
        )}
      </div>

      {/* Filters */}
      {showFilters && (
        <div className="flex gap-3 p-3 border-b dark:border-gray-700">
          <select
            value={filter.decision}
            onChange={(e) => setFilter((f) => ({ ...f, decision: e.target.value as 'all' | 'allow' | 'deny' }))}
            className="px-2 py-1 text-sm rounded-md border dark:border-gray-600 dark:bg-gray-700 dark:text-white"
          >
            <option value="all">All Decisions</option>
            <option value="allow">Allowed</option>
            <option value="deny">Denied</option>
          </select>
          <select
            value={filter.riskTier}
            onChange={(e) => setFilter((f) => ({ ...f, riskTier: e.target.value as 'all' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' }))}
            className="px-2 py-1 text-sm rounded-md border dark:border-gray-600 dark:bg-gray-700 dark:text-white"
          >
            <option value="all">All Risk Tiers</option>
            <option value="LOW">Low</option>
            <option value="MEDIUM">Medium</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>
          <input
            type="text"
            placeholder="Search actions, agents..."
            value={filter.search}
            onChange={(e) => setFilter((f) => ({ ...f, search: e.target.value }))}
            className="flex-1 px-3 py-1 text-sm rounded-md border dark:border-gray-600 dark:bg-gray-700 dark:text-white"
          />
        </div>
      )}

      {/* Event List */}
      <div className="flex-1 overflow-y-auto">
        {filteredEvents.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-gray-500 dark:text-gray-400">
            {events.length === 0 ? 'Waiting for events...' : 'No events match the current filters'}
          </div>
        ) : (
          <div className="divide-y dark:divide-gray-700">
            {filteredEvents.map((event) => (
              <ActivityEventRow
                key={event.id}
                event={event}
                isHighlighted={highlightedIds.has(event.id)}
                onClick={onEventClick}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ActivityEventRow({
  event,
  isHighlighted,
  onClick,
}: {
  event: ActivityEvent;
  isHighlighted: boolean;
  onClick?: (event: ActivityEvent) => void;
}) {
  const agentName = event.agent.split('/').pop() || event.agent;
  const timeAgo = formatDistanceToNow(new Date(event.timestamp), { addSuffix: true });

  return (
    <div
      className={`p-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer transition-all duration-300 ${
        isHighlighted ? 'bg-blue-50 dark:bg-blue-900/20 animate-pulse' : ''
      }`}
      onClick={() => onClick?.(event)}
    >
      <div className="flex items-start gap-3">
        {/* Decision indicator */}
        <div className={`w-2 h-2 mt-2 rounded-full ${DECISION_COLORS[event.decision]}`} />

        {/* Main content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm text-gray-900 dark:text-white truncate">{event.action}</span>
            <span className={`px-1.5 py-0.5 text-xs rounded ${RISK_TIER_COLORS[event.riskTier]}`}>
              {event.riskTier}
            </span>
            {event.timePolicyViolation && (
              <span className="px-1.5 py-0.5 text-xs rounded bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300">
                {TIME_VIOLATION_LABELS[event.timePolicyViolation]}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 mt-1 text-xs text-gray-500 dark:text-gray-400">
            <span title={event.agent}>{agentName}</span>
            <span>•</span>
            <span title={format(new Date(event.timestamp), 'PPpp')}>{timeAgo}</span>
            <span>•</span>
            <span>{event.durationMs}ms</span>
            {event.jurisdiction && (
              <>
                <span>•</span>
                <span className="font-medium">{event.jurisdiction}</span>
              </>
            )}
          </div>
          {event.reason && (
            <div className="mt-1 text-xs text-red-600 dark:text-red-400">
              {event.reason}
            </div>
          )}
        </div>

        {/* Decision badge */}
        <span
          className={`px-2 py-1 text-xs font-medium rounded ${
            event.decision === 'allow'
              ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300'
              : 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300'
          }`}
        >
          {event.decision.toUpperCase()}
        </span>
      </div>
    </div>
  );
}

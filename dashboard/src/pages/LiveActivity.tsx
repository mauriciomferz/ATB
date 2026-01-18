import { useState, useEffect, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchAuditEvents } from '../api';
import ActivityFeed from '../components/ActivityFeed';

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

// Mock function to generate realistic events with new time policy features
function generateMockEvent(): ActivityEvent {
  const actions = [
    'sap.vendor.change',
    'sap.vendor.read',
    'crm.contact.update',
    'salesforce.bulk.export',
    'sap.payment.approve',
    'org.structure.modify',
    'security.admin.grant',
    'finance.ledger.close',
  ];

  const agents = [
    'spiffe://atb.example/agent/copilot-prod',
    'spiffe://atb.example/agent/finance-bot',
    'spiffe://atb.example/agent/data-sync',
    'spiffe://atb.example/agent/hr-assistant',
    'spiffe://atb.example/agent/security-monitor',
  ];

  const tiers: Array<'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'> = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const tierWeights = [50, 30, 15, 5]; // Weighted distribution

  const jurisdictions = ['DE', 'US', 'GB', 'FR', 'GLOBAL'];

  const reasons = [
    'liability_cap exceeded',
    'missing_poa',
    'invalid_signature',
    'dual_control_required',
    'rate_limit_exceeded',
    'outside_business_hours',
    'approval_expired',
    'executive_approval_required',
  ];

  const timeViolations: Array<'rate_limit_exceeded' | 'outside_business_hours' | 'approval_expired' | undefined> = [
    undefined,
    undefined,
    undefined, // Most events have no violation
    'rate_limit_exceeded',
    'outside_business_hours',
    'approval_expired',
  ];

  // Weighted random tier selection
  const rand = Math.random() * 100;
  let cumulative = 0;
  let selectedTier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
  for (let i = 0; i < tiers.length; i++) {
    cumulative += tierWeights[i];
    if (rand < cumulative) {
      selectedTier = tiers[i];
      break;
    }
  }

  // Higher risk = higher chance of denial
  const denyChance = { LOW: 0.02, MEDIUM: 0.08, HIGH: 0.15, CRITICAL: 0.25 };
  const isDenied = Math.random() < denyChance[selectedTier];

  const timeViolation = isDenied ? timeViolations[Math.floor(Math.random() * timeViolations.length)] : undefined;

  return {
    id: `evt_${Date.now()}_${Math.random().toString(36).slice(2)}`,
    timestamp: new Date().toISOString(),
    action: actions[Math.floor(Math.random() * actions.length)],
    agent: agents[Math.floor(Math.random() * agents.length)],
    decision: isDenied ? 'deny' : 'allow',
    riskTier: selectedTier,
    durationMs: Math.floor(Math.random() * 80) + 5,
    reason: isDenied ? reasons[Math.floor(Math.random() * reasons.length)] : undefined,
    jurisdiction: jurisdictions[Math.floor(Math.random() * jurisdictions.length)],
    timePolicyViolation: timeViolation,
  };
}

export default function LiveActivity() {
  const queryClient = useQueryClient();
  const [isLive, setIsLive] = useState(true);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<ActivityEvent | null>(null);
  const [connectionStatus, setConnectionStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');

  // Fetch initial events
  const { data: initialEvents } = useQuery({
    queryKey: ['audit', 'live'],
    queryFn: () => fetchAuditEvents(50),
    refetchOnWindowFocus: false,
  });

  // Initialize with fetched events
  useEffect(() => {
    if (initialEvents) {
      setEvents(initialEvents.map(e => ({ ...e, riskTier: e.riskTier as ActivityEvent['riskTier'] })));
      setConnectionStatus('connected');
    }
  }, [initialEvents]);

  // Simulate WebSocket connection with mock events
  useEffect(() => {
    if (!isLive) return;

    // In production, this would be a WebSocket connection
    // For development, we simulate incoming events
    const simulateEvent = () => {
      if (Math.random() < 0.7) { // 70% chance of event each interval
        const newEvent = generateMockEvent();
        setEvents((prev) => [newEvent, ...prev].slice(0, 200));

        // Update query cache for other components
        queryClient.setQueryData(['audit', 'recent'], (old: ActivityEvent[] | undefined) => {
          if (!old) return [newEvent];
          return [newEvent, ...old].slice(0, 100);
        });
      }
    };

    const interval = setInterval(simulateEvent, 1500 + Math.random() * 1500);
    return () => clearInterval(interval);
  }, [isLive, queryClient]);

  const handleToggleLive = useCallback(() => {
    setIsLive((prev) => !prev);
  }, []);

  const handleEventClick = useCallback((event: ActivityEvent) => {
    setSelectedEvent(event);
  }, []);

  const closeEventDetail = useCallback(() => {
    setSelectedEvent(null);
  }, []);

  return (
    <div className="h-[calc(100vh-8rem)]">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Live Activity Monitor</h1>
          <p className="text-gray-600 dark:text-gray-400">
            Real-time view of authorization decisions
          </p>
        </div>
        <div className="flex items-center gap-4">
          <ConnectionIndicator status={connectionStatus} />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-[calc(100%-4rem)]">
        {/* Main Activity Feed */}
        <div className="lg:col-span-2 card h-full overflow-hidden">
          <ActivityFeed
            events={events}
            maxEvents={100}
            showFilters={true}
            isLive={isLive}
            onToggleLive={handleToggleLive}
            onEventClick={handleEventClick}
          />
        </div>

        {/* Side Panel */}
        <div className="space-y-4">
          {/* Event Detail */}
          {selectedEvent ? (
            <EventDetailPanel event={selectedEvent} onClose={closeEventDetail} />
          ) : (
            <div className="card p-4">
              <h3 className="text-lg font-medium dark:text-white mb-2">Event Details</h3>
              <p className="text-gray-500 dark:text-gray-400 text-sm">
                Click on an event to view details
              </p>
            </div>
          )}

          {/* Quick Stats */}
          <LiveStatsPanel events={events} />
        </div>
      </div>
    </div>
  );
}

function ConnectionIndicator({ status }: { status: 'connecting' | 'connected' | 'disconnected' }) {
  const colors = {
    connecting: 'bg-yellow-500',
    connected: 'bg-green-500',
    disconnected: 'bg-red-500',
  };

  const labels = {
    connecting: 'Connecting...',
    connected: 'Connected',
    disconnected: 'Disconnected',
  };

  return (
    <div className="flex items-center gap-2 text-sm">
      <span className={`w-2 h-2 rounded-full ${colors[status]}`} />
      <span className="text-gray-600 dark:text-gray-400">{labels[status]}</span>
    </div>
  );
}

function EventDetailPanel({ event, onClose }: { event: ActivityEvent; onClose: () => void }) {
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-lg font-medium dark:text-white">Event Details</h3>
        <button
          onClick={onClose}
          className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
        >
          ✕
        </button>
      </div>

      <dl className="space-y-3 text-sm">
        <DetailRow label="Event ID" value={event.id} mono />
        <DetailRow label="Timestamp" value={new Date(event.timestamp).toLocaleString()} />
        <DetailRow label="Action" value={event.action} mono />
        <DetailRow label="Agent" value={event.agent} mono truncate />
        <DetailRow
          label="Decision"
          value={
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium ${
                event.decision === 'allow'
                  ? 'bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300'
                  : 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300'
              }`}
            >
              {event.decision.toUpperCase()}
            </span>
          }
        />
        <DetailRow
          label="Risk Tier"
          value={
            <span
              className={`px-2 py-0.5 rounded text-xs font-medium ${
                event.riskTier === 'LOW'
                  ? 'bg-green-100 text-green-800 dark:bg-green-900/40'
                  : event.riskTier === 'MEDIUM'
                  ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40'
                  : event.riskTier === 'HIGH'
                  ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/40'
                  : 'bg-red-100 text-red-800 dark:bg-red-900/40'
              }`}
            >
              {event.riskTier}
            </span>
          }
        />
        <DetailRow label="Latency" value={`${event.durationMs}ms`} />
        {event.jurisdiction && <DetailRow label="Jurisdiction" value={event.jurisdiction} />}
        {event.reason && (
          <DetailRow label="Reason" value={event.reason} className="text-red-600 dark:text-red-400" />
        )}
        {event.timePolicyViolation && (
          <DetailRow
            label="Time Policy"
            value={
              <span className="px-2 py-0.5 rounded text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-900/40 dark:text-purple-300">
                {event.timePolicyViolation.replace(/_/g, ' ')}
              </span>
            }
          />
        )}
      </dl>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono = false,
  truncate = false,
  className = '',
}: {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
  truncate?: boolean;
  className?: string;
}) {
  return (
    <div className="flex justify-between items-start gap-2">
      <dt className="text-gray-500 dark:text-gray-400 flex-shrink-0">{label}</dt>
      <dd
        className={`text-right ${mono ? 'font-mono text-xs' : ''} ${truncate ? 'truncate' : ''} ${className} text-gray-900 dark:text-white`}
        title={typeof value === 'string' ? value : undefined}
      >
        {value}
      </dd>
    </div>
  );
}

function LiveStatsPanel({ events }: { events: ActivityEvent[] }) {
  const stats = {
    total: events.length,
    allowed: events.filter((e) => e.decision === 'allow').length,
    denied: events.filter((e) => e.decision === 'deny').length,
    critical: events.filter((e) => e.riskTier === 'CRITICAL').length,
    high: events.filter((e) => e.riskTier === 'HIGH').length,
    rateLimit: events.filter((e) => e.timePolicyViolation === 'rate_limit_exceeded').length,
    afterHours: events.filter((e) => e.timePolicyViolation === 'outside_business_hours').length,
    expired: events.filter((e) => e.timePolicyViolation === 'approval_expired').length,
  };

  const avgLatency =
    events.length > 0
      ? Math.round(events.reduce((sum, e) => sum + e.durationMs, 0) / events.length)
      : 0;

  return (
    <div className="card p-4">
      <h3 className="text-lg font-medium dark:text-white mb-3">Session Stats</h3>

      <div className="space-y-2 text-sm">
        <div className="flex justify-between">
          <span className="text-gray-600 dark:text-gray-400">Total Events</span>
          <span className="font-bold dark:text-white">{stats.total}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-green-600 dark:text-green-400">Allowed</span>
          <span className="font-bold text-green-600 dark:text-green-400">{stats.allowed}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-red-600 dark:text-red-400">Denied</span>
          <span className="font-bold text-red-600 dark:text-red-400">{stats.denied}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-gray-600 dark:text-gray-400">Avg Latency</span>
          <span className="font-bold dark:text-white">{avgLatency}ms</span>
        </div>

        <hr className="my-2 dark:border-gray-700" />

        <div className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1">
          Risk Tiers
        </div>
        <div className="flex justify-between">
          <span className="text-red-700 dark:text-red-300">Critical</span>
          <span className="font-bold text-red-700 dark:text-red-300">{stats.critical}</span>
        </div>
        <div className="flex justify-between">
          <span className="text-orange-600 dark:text-orange-400">High</span>
          <span className="font-bold text-orange-600 dark:text-orange-400">{stats.high}</span>
        </div>

        {(stats.rateLimit > 0 || stats.afterHours > 0 || stats.expired > 0) && (
          <>
            <hr className="my-2 dark:border-gray-700" />
            <div className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase mb-1">
              Time Policy Violations
            </div>
            {stats.rateLimit > 0 && (
              <div className="flex justify-between">
                <span className="text-purple-600 dark:text-purple-400">Rate Limit</span>
                <span className="font-bold text-purple-600 dark:text-purple-400">{stats.rateLimit}</span>
              </div>
            )}
            {stats.afterHours > 0 && (
              <div className="flex justify-between">
                <span className="text-purple-600 dark:text-purple-400">After Hours</span>
                <span className="font-bold text-purple-600 dark:text-purple-400">{stats.afterHours}</span>
              </div>
            )}
            {stats.expired > 0 && (
              <div className="flex justify-between">
                <span className="text-purple-600 dark:text-purple-400">Expired</span>
                <span className="font-bold text-purple-600 dark:text-purple-400">{stats.expired}</span>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

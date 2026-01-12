import { useEffect, useCallback } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useWebSocket } from './useWebSocket';
import { useNotifications } from '../context/NotificationContext';
import { useSettings } from '../context/SettingsContext';

interface AuditEvent {
  id: string;
  timestamp: string;
  action: string;
  agent: string;
  decision: 'allow' | 'deny';
  riskTier: 'LOW' | 'MEDIUM' | 'HIGH';
  durationMs: number;
}

export function useRealtimeEvents() {
  const queryClient = useQueryClient();
  const { addNotification } = useNotifications();
  const { settings } = useSettings();

  const handleMessage = useCallback(
    (message: { type: string; data: unknown }) => {
      switch (message.type) {
        case 'audit_event': {
          const event = message.data as AuditEvent;
          
          // Update the audit events cache
          queryClient.setQueryData(['audit', 'recent'], (old: AuditEvent[] | undefined) => {
            if (!old) return [event];
            return [event, ...old].slice(0, 100);
          });

          // Show notification for denied or high-risk events
          if (settings.notifications) {
            if (event.decision === 'deny') {
              addNotification({
                type: 'warning',
                title: 'Authorization Denied',
                message: `${event.action} by ${event.agent.split('/').pop()}`,
              });
            } else if (event.riskTier === 'HIGH') {
              addNotification({
                type: 'info',
                title: 'High-Risk Action',
                message: `${event.action} approved for ${event.agent.split('/').pop()}`,
              });
            }
          }
          break;
        }

        case 'health_update': {
          queryClient.invalidateQueries({ queryKey: ['health'] });
          break;
        }

        case 'metrics_update': {
          queryClient.invalidateQueries({ queryKey: ['metrics'] });
          break;
        }

        case 'alert': {
          const alert = message.data as { severity: 'critical' | 'warning' | 'info'; message: string };
          if (settings.notifications) {
            addNotification({
              type: alert.severity === 'critical' ? 'error' : alert.severity,
              title: 'System Alert',
              message: alert.message,
              duration: alert.severity === 'critical' ? 0 : 5000, // Critical alerts don't auto-dismiss
            });
          }
          break;
        }
      }
    },
    [queryClient, addNotification, settings.notifications]
  );

  const { isConnected, lastMessage, reconnect } = useWebSocket({
    url: `${settings.apiUrl.replace('http', 'ws')}/ws`,
    onMessage: handleMessage,
    onOpen: () => {
      if (settings.notifications) {
        addNotification({
          type: 'success',
          title: 'Connected',
          message: 'Real-time updates enabled',
          duration: 2000,
        });
      }
    },
    onClose: () => {
      if (settings.notifications) {
        addNotification({
          type: 'warning',
          title: 'Disconnected',
          message: 'Attempting to reconnect...',
          duration: 3000,
        });
      }
    },
  });

  return { isConnected, lastMessage, reconnect };
}

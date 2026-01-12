import { useQuery } from '@tanstack/react-query';
import { fetchSystemHealth } from '../api';

export default function ConnectionStatus() {
  const { data: health, isLoading, isError, dataUpdatedAt } = useQuery({
    queryKey: ['health'],
    queryFn: fetchSystemHealth,
    refetchInterval: 5000,
  });

  const isConnected = !isError && health?.broker.status === 'healthy';
  const lastUpdate = dataUpdatedAt ? new Date(dataUpdatedAt).toLocaleTimeString() : '-';

  return (
    <div className="flex items-center gap-3 text-sm">
      <div className="flex items-center gap-2">
        {isLoading ? (
          <span className="w-2 h-2 bg-gray-400 rounded-full animate-pulse" />
        ) : (
          <span
            className={`w-2 h-2 rounded-full ${
              isConnected ? 'bg-green-500' : 'bg-red-500'
            } ${isConnected ? 'animate-pulse' : ''}`}
          />
        )}
        <span className="text-gray-600 dark:text-gray-400">
          {isLoading ? 'Connecting...' : isConnected ? 'Connected' : 'Disconnected'}
        </span>
      </div>
      {!isLoading && (
        <span className="text-gray-400 dark:text-gray-500 text-xs">
          Last: {lastUpdate}
        </span>
      )}
    </div>
  );
}

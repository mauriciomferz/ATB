import type { AuditEvent } from '../types';

interface ExportButtonProps {
  data: AuditEvent[];
  filename?: string;
}

export default function ExportButton({ data, filename = 'audit-log' }: ExportButtonProps) {
  const exportToCSV = () => {
    if (data.length === 0) {
      alert('No data to export');
      return;
    }

    const headers = [
      'ID',
      'Timestamp',
      'Action',
      'Agent',
      'Decision',
      'Risk Tier',
      'Accountable Party',
      'Jurisdiction',
      'Duration (ms)',
      'Reason',
    ];

    const rows = data.map((event) => [
      event.id,
      event.timestamp,
      event.action,
      event.agent,
      event.decision,
      event.riskTier,
      event.accountableParty.displayName || event.accountableParty.id,
      event.jurisdiction,
      event.durationMs,
      event.reason || '',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map((row) =>
        row.map((cell) => `"${String(cell).replace(/"/g, '""')}"`).join(',')
      ),
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `${filename}-${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const exportToJSON = () => {
    if (data.length === 0) {
      alert('No data to export');
      return;
    }

    const jsonContent = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonContent], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `${filename}-${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="relative inline-block">
      <div className="flex gap-2">
        <button
          onClick={exportToCSV}
          className="btn bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600 text-sm"
        >
          📥 CSV
        </button>
        <button
          onClick={exportToJSON}
          className="btn bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600 text-sm"
        >
          📥 JSON
        </button>
      </div>
    </div>
  );
}

import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from 'recharts';

interface RiskDistributionProps {
  data: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
  };
}

const COLORS = {
  LOW: '#22c55e',
  MEDIUM: '#f59e0b',
  HIGH: '#ef4444',
};

export default function RiskDistributionChart({ data }: RiskDistributionProps) {
  const chartData = [
    { name: 'Low Risk', value: data.LOW, color: COLORS.LOW },
    { name: 'Medium Risk', value: data.MEDIUM, color: COLORS.MEDIUM },
    { name: 'High Risk', value: data.HIGH, color: COLORS.HIGH },
  ].filter((item) => item.value > 0);

  const total = data.LOW + data.MEDIUM + data.HIGH;

  if (total === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500 dark:text-gray-400">
        No data available
      </div>
    );
  }

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
            labelLine={false}
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            formatter={(value: number) => [value.toLocaleString(), 'Requests']}
            contentStyle={{
              backgroundColor: 'rgba(255, 255, 255, 0.95)',
              border: '1px solid #e5e7eb',
              borderRadius: '8px',
            }}
          />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

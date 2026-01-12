import { useState } from 'react';
import { useSettings } from '../context/SettingsContext';
import { useTheme } from '../context/ThemeContext';

export default function Settings() {
  const { settings, updateSettings, resetSettings } = useSettings();
  const { theme, toggleTheme } = useTheme();
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>

      {/* Appearance */}
      <div className="card">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Appearance</h2>
        <div className="flex items-center justify-between">
          <div>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Dark Mode
            </label>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Toggle dark theme for the dashboard
            </p>
          </div>
          <button
            onClick={toggleTheme}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              theme === 'dark' ? 'bg-primary-600' : 'bg-gray-300'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                theme === 'dark' ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>

      {/* API Configuration */}
      <div className="card">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">API Configuration</h2>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              ATB Broker URL
            </label>
            <input
              type="text"
              value={settings.apiUrl}
              onChange={(e) => updateSettings({ apiUrl: e.target.value })}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
              placeholder="http://localhost:8080"
            />
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              The base URL for the ATB broker API
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Refresh Interval (seconds)
            </label>
            <select
              value={settings.refreshInterval}
              onChange={(e) => updateSettings({ refreshInterval: Number(e.target.value) })}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
            >
              <option value={5}>5 seconds</option>
              <option value={10}>10 seconds</option>
              <option value={30}>30 seconds</option>
              <option value={60}>1 minute</option>
              <option value={300}>5 minutes</option>
            </select>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              How often to refresh dashboard data
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Max Audit Events
            </label>
            <select
              value={settings.maxAuditEvents}
              onChange={(e) => updateSettings({ maxAuditEvents: Number(e.target.value) })}
              className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
            >
              <option value={50}>50 events</option>
              <option value={100}>100 events</option>
              <option value={200}>200 events</option>
              <option value={500}>500 events</option>
            </select>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Maximum audit events to display in the log
            </p>
          </div>
        </div>
      </div>

      {/* Notifications */}
      <div className="card">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">Notifications</h2>
        <div className="flex items-center justify-between">
          <div>
            <label className="text-sm font-medium text-gray-700 dark:text-gray-300">
              Show Notifications
            </label>
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Display browser notifications for denied actions
            </p>
          </div>
          <button
            onClick={() => updateSettings({ showNotifications: !settings.showNotifications })}
            className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              settings.showNotifications ? 'bg-primary-600' : 'bg-gray-300'
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                settings.showNotifications ? 'translate-x-6' : 'translate-x-1'
              }`}
            />
          </button>
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-4">
        <button onClick={handleSave} className="btn btn-primary">
          {saved ? '✓ Saved' : 'Save Settings'}
        </button>
        <button
          onClick={resetSettings}
          className="btn bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600"
        >
          Reset to Defaults
        </button>
      </div>

      {/* About */}
      <div className="card">
        <h2 className="text-lg font-medium text-gray-900 dark:text-white mb-4">About</h2>
        <dl className="space-y-2 text-sm">
          <div className="flex justify-between">
            <dt className="text-gray-500 dark:text-gray-400">Dashboard Version</dt>
            <dd className="text-gray-900 dark:text-gray-100">0.1.0</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500 dark:text-gray-400">ATB Version</dt>
            <dd className="text-gray-900 dark:text-gray-100">0.1.0</dd>
          </div>
          <div className="flex justify-between">
            <dt className="text-gray-500 dark:text-gray-400">Documentation</dt>
            <dd>
              <a href="https://github.com/mauriciomferz/ATB" className="text-primary-600 dark:text-primary-400 hover:underline">
                GitHub Repository
              </a>
            </dd>
          </div>
        </dl>
      </div>
    </div>
  );
}

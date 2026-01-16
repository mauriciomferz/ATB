import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import AuditLog from './pages/AuditLog';
import Policies from './pages/Policies';
import Agents from './pages/Agents';
import Approvals from './pages/Approvals';
import TokenInspector from './pages/TokenInspector';
import Settings from './pages/Settings';
import Users from './pages/Users';
import ThemeToggle from './components/ThemeToggle';
import ConnectionStatus from './components/ConnectionStatus';
import ToastContainer from './components/ToastContainer';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
        {/* Navigation */}
        <nav className="bg-white dark:bg-gray-800 shadow-sm border-b dark:border-gray-700">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex">
                <div className="flex-shrink-0 flex items-center">
                  <span className="text-xl font-bold text-primary-600">ATB</span>
                  <span className="ml-2 text-gray-600 dark:text-gray-400">Dashboard</span>
                </div>
                <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
                  <NavLink to="/">Overview</NavLink>
                  <NavLink to="/audit">Audit Log</NavLink>
                  <NavLink to="/approvals">Approvals</NavLink>
                  <NavLink to="/policies">Policies</NavLink>
                  <NavLink to="/agents">Agents</NavLink>
                  <NavLink to="/users">Users</NavLink>
                  <NavLink to="/token">Token Inspector</NavLink>
                  <NavLink to="/settings">Settings</NavLink>
                </div>
              </div>
              <div className="flex items-center gap-4">
                <ConnectionStatus />
                <ThemeToggle />
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/users" element={<Users />} />
            <Route path="/token" element={<TokenInspector />} />
            <Route path="/settings" element={<Settings />} />
          </Routes>
        </main>
        <ToastContainer />
      </div>
    </BrowserRouter>
  );
}

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  const location = useLocation();
  const isActive = location.pathname === to;

  return (
    <Link
      to={to}
      className={`inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium transition-colors ${
        isActive
          ? 'border-primary-500 text-primary-600 dark:text-primary-400'
          : 'border-transparent text-gray-500 dark:text-gray-400 hover:border-gray-300 hover:text-gray-700 dark:hover:text-gray-300'
      }`}
    >
      {children}
    </Link>
  );
}

export default App;

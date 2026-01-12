import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import AuditLog from './pages/AuditLog';
import Policies from './pages/Policies';
import Agents from './pages/Agents';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-50">
        {/* Navigation */}
        <nav className="bg-white shadow-sm border-b">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex">
                <div className="flex-shrink-0 flex items-center">
                  <span className="text-xl font-bold text-primary-600">ATB</span>
                  <span className="ml-2 text-gray-600">Dashboard</span>
                </div>
                <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
                  <NavLink to="/">Overview</NavLink>
                  <NavLink to="/audit">Audit Log</NavLink>
                  <NavLink to="/policies">Policies</NavLink>
                  <NavLink to="/agents">Agents</NavLink>
                </div>
              </div>
              <div className="flex items-center">
                <span className="text-sm text-gray-500">
                  <span className="inline-block w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                  Connected
                </span>
              </div>
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/audit" element={<AuditLog />} />
            <Route path="/policies" element={<Policies />} />
            <Route path="/agents" element={<Agents />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}

function NavLink({ to, children }: { to: string; children: React.ReactNode }) {
  return (
    <Link
      to={to}
      className="inline-flex items-center px-1 pt-1 border-b-2 border-transparent text-sm font-medium text-gray-500 hover:border-gray-300 hover:text-gray-700"
    >
      {children}
    </Link>
  );
}

export default App;

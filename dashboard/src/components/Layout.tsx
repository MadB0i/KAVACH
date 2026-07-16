import { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';

const navItems = [
  { to: '/', label: 'Overview', icon: '\u2302' },
  { to: '/live-requests', label: 'Live Requests', icon: '\u25B6' },
  { to: '/approvals', label: 'Pending Approvals', icon: '\u2691' },
  { to: '/audit', label: 'Audit Timeline', icon: '\u29D6' },
  { to: '/policies', label: 'Policies', icon: '\u2699' },
  { to: '/agents', label: 'Agents/Sessions', icon: '\u263C' },
  { to: '/warnings', label: 'Security Warnings', icon: '\u26A0' },
  { to: '/health', label: 'System Health', icon: '\u2665' },
  { to: '/config', label: 'Configuration', icon: '\u2630' },
  { to: '/audit-verify', label: 'Audit Verification', icon: '\u2713' },
];

export default function Layout() {
  const { isAuthenticated, actor, logout } = useAuth();
  const { toggleTheme, isDark } = useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="app-layout">
      <button
        className="sidebar-toggle"
        onClick={() => setSidebarOpen(!sidebarOpen)}
        aria-label={sidebarOpen ? 'Close sidebar' : 'Open sidebar'}
        aria-expanded={sidebarOpen}
      >
        {sidebarOpen ? '\u2715' : '\u2630'}
      </button>

      <aside className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''}`} role="navigation" aria-label="Main navigation">
        <div className="sidebar__header">
          <h2 className="sidebar__title">KAVACH</h2>
          <p className="sidebar__subtitle">Dashboard</p>
        </div>
        <nav>
          <ul className="sidebar__nav">
            {navItems.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) => `sidebar__link ${isActive ? 'sidebar__link--active' : ''}`}
                  onClick={() => setSidebarOpen(false)}
                  aria-label={item.label}
                >
                  <span className="sidebar__icon" aria-hidden="true">{item.icon}</span>
                  <span>{item.label}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
      </aside>

      <div className="main-area" role="main">
        <header className="topbar">
          <div className="topbar__left">
            <h1 className="topbar__title">KAVACH Dashboard</h1>
          </div>
          <div className="topbar__right">
            <span
              className={`connection-status ${isAuthenticated ? 'connection-status--connected' : 'connection-status--disconnected'}`}
              aria-label={isAuthenticated ? 'Connected to API' : 'Disconnected'}
              title={isAuthenticated ? 'Connected' : 'Disconnected'}
            />
            {actor && <span className="topbar__actor" title="Authenticated as">{actor}</span>}
            <button
              className="btn btn--ghost btn--icon"
              onClick={toggleTheme}
              aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
              title={isDark ? 'Light mode' : 'Dark mode'}
            >
              {isDark ? '\u2600' : '\u263E'}
            </button>
            <button className="btn btn--ghost" onClick={handleLogout} aria-label="Logout">
              Logout
            </button>
          </div>
        </header>
        <div className="content">
          <Outlet />
        </div>
      </div>

      {sidebarOpen && (
        <div
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}
    </div>
  );
}

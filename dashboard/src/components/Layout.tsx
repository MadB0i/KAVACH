import { useState, useCallback } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { useTheme } from '../context/useTheme';

const navItems = [
  { to: '/', label: 'Overview', icon: '\u25A6' },
  { to: '/live-requests', label: 'Live Requests', icon: '\u25B6' },
  { to: '/approvals', label: 'Pending Approvals', icon: '\u2691' },
  { to: '/audit', label: 'Audit Timeline', icon: '\u29D6' },
  { to: '/audit-verify', label: 'Audit Verification', icon: '\u2713' },
  { to: '/policies', label: 'Policies', icon: '\u2699' },
  { to: '/agents', label: 'Agents/Sessions', icon: '\u25CB' },
  { to: '/warnings', label: 'Security Warnings', icon: '\u26A0' },
  { to: '/health', label: 'System Health', icon: '\u2665' },
  { to: '/config', label: 'Configuration', icon: '\u2630' },
];

export default function Layout() {
  const { isAuthenticated, actor, logout } = useAuth();
  const { toggleTheme, isDark } = useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();

  const handleLogout = useCallback(() => {
    logout();
    navigate('/login');
  }, [logout, navigate]);

  const handleCollapse = useCallback(() => {
    setCollapsed((prev) => !prev);
  }, []);

  const closeSidebar = useCallback(() => setSidebarOpen(false), []);

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

      <aside
        className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''} ${collapsed ? 'sidebar--collapsed' : ''}`}
        role="navigation"
        aria-label="Main navigation"
      >
        <div className="sidebar__brand">
          <div className="sidebar__logo">K</div>
          <div className="sidebar__brand-text">
            <div className="sidebar__brand-name">KAVACH</div>
            <div className="sidebar__brand-sub">Zero-Trust Runtime</div>
          </div>
        </div>

        <div className="sidebar__nav-wrap">
          <div className="sidebar__section-label">Navigation</div>
          <ul className="sidebar__nav">
            {navItems.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) => `sidebar__link ${isActive ? 'sidebar__link--active' : ''}`}
                  onClick={closeSidebar}
                  aria-label={item.label}
                >
                  <span className="sidebar__icon" aria-hidden="true">{item.icon}</span>
                  <span className="sidebar__label">{item.label}</span>
                </NavLink>
              </li>
            ))}
          </ul>
        </div>

        <div className="sidebar__footer">
          <button
            className="sidebar__collapse-btn"
            onClick={handleCollapse}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <span className="sidebar__icon">{collapsed ? '\u203A' : '\u2039'}</span>
            <span className="sidebar__label">{collapsed ? '' : 'Collapse'}</span>
          </button>
        </div>
      </aside>

      <div className="main-area" role="main">
        <header className="topbar">
          <div className="topbar__left">
            <span className="topbar__breadcrumb">KAVACH</span>
          </div>

          <div className="topbar__search">
            <span className="topbar__search-icon">{'\u2315'}</span>
            <input
              className="topbar__search-input"
              type="search"
              placeholder="Search events, requests..."
              aria-label="Global search"
            />
          </div>

          <div className="topbar__right">
            <span
              className={`topbar__btn topbar__btn--indicator ${isAuthenticated ? 'topbar__btn--connected' : 'topbar__btn--disconnected'}`}
              aria-label={isAuthenticated ? 'Connected' : 'Disconnected'}
              title={isAuthenticated ? 'Gateway connected' : 'Gateway disconnected'}
            >
              {'\u25CF'}
            </span>

            {actor && <span className="topbar__actor" title={actor}>{actor}</span>}

            <span className="topbar__divider" />

            <button
              className="topbar__btn"
              onClick={toggleTheme}
              aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
              title={isDark ? 'Light mode' : 'Dark mode'}
            >
              {isDark ? '\u2600' : '\u263E'}
            </button>

            <button
              className="btn btn--ghost btn--sm"
              onClick={handleLogout}
              aria-label="Logout"
              title="Logout"
            >
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
          onClick={closeSidebar}
          aria-hidden="true"
        />
      )}
    </div>
  );
}

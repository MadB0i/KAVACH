import { useState, useCallback, useEffect } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { useTheme } from '../context/useTheme';
import { getStatus } from '../api';

const navItems = [
  { to: '/', label: 'Overview', icon: 'overview' },
  { to: '/live-requests', label: 'Live Requests', icon: 'activity' },
  { to: '/approvals', label: 'Pending Approvals', icon: 'approval' },
  { to: '/audit', label: 'Audit Timeline', icon: 'timeline' },
  { to: '/audit-verify', label: 'Audit Verification', icon: 'verify' },
  { to: '/policies', label: 'Policies', icon: 'policy' },
  { to: '/agents', label: 'Agents/Sessions', icon: 'agents' },
  { to: '/warnings', label: 'Security Warnings', icon: 'warning' },
  { to: '/health', label: 'System Health', icon: 'health' },
  { to: '/config', label: 'Configuration', icon: 'config' },
];

const iconPaths: Record<string, string[]> = {
  overview: ['M4 4h6v6H4z', 'M14 4h6v6h-6z', 'M4 14h6v6H4z', 'M14 14h6v6h-6z'],
  activity: ['M3 12h4l2.5-6 5 12 2.5-6H21'],
  approval: ['M12 3l7 3v5c0 4.5-2.8 8-7 10-4.2-2-7-5.5-7-10V6z', 'm9 12 2 2 4-5'],
  timeline: ['M5 5h14', 'M5 12h14', 'M5 19h14', 'M8 5v14'],
  verify: ['M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z', 'm8 12 3 3 5-6'],
  policy: ['M4 6h16', 'M4 12h16', 'M4 18h16', 'M8 4v4', 'M16 10v4', 'M10 16v4'],
  agents: ['M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2', 'M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M22 21v-2a4 4 0 0 0-3-3.87'],
  warning: ['M12 3 2 21h20z', 'M12 9v5', 'M12 18h.01'],
  health: ['M3 12h4l2-5 4 10 2-5h6'],
  config: ['M5 4h14v16H5z', 'M8 8h8', 'M8 12h5', 'M8 16h7'],
};

function NavIcon({ name }: { name: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      {iconPaths[name]?.map((path) => <path key={path} d={path} />)}
    </svg>
  );
}

export default function Layout() {
  const { actor, logout } = useAuth();
  const { toggleTheme, isDark } = useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [search, setSearch] = useState('');
  const [gatewayOnline, setGatewayOnline] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();

  const handleLogout = useCallback(() => {
    logout();
    navigate('/login');
  }, [logout, navigate]);

  const handleCollapse = useCallback(() => {
    setCollapsed((prev) => !prev);
  }, []);

  const closeSidebar = useCallback(() => setSidebarOpen(false), []);
  const activePage = navItems.find((item) => item.to === location.pathname)?.label || 'Security Console';

  useEffect(() => {
    let mounted = true;
    const checkGateway = async () => {
      try {
        await getStatus();
        if (mounted) setGatewayOnline(true);
      } catch {
        if (mounted) setGatewayOnline(false);
      }
    };
    const interval = window.setInterval(checkGateway, 15000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, []);

  const handleSearch = (event: React.FormEvent) => {
    event.preventDefault();
    const query = search.trim();
    if (query) navigate(`/audit?request=${encodeURIComponent(query)}`);
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

      <aside
        className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''} ${collapsed ? 'sidebar--collapsed' : ''}`}
        role="navigation"
        aria-label="Main navigation"
      >
        <div className="sidebar__brand">
          <div className="sidebar__logo" aria-hidden="true">K</div>
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
                  <span className="sidebar__icon"><NavIcon name={item.icon} /></span>
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
            <span className="topbar__breadcrumb">KAVACH / <strong>{activePage}</strong></span>
          </div>

          <form className="topbar__search" onSubmit={handleSearch}>
            <span className="topbar__search-icon">{'\u2315'}</span>
            <input
              className="topbar__search-input"
              type="search"
              placeholder="Search events, requests..."
              aria-label="Global search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
            <kbd>Enter</kbd>
          </form>

          <div className="topbar__right">
            <span
              className={`topbar__btn topbar__btn--indicator ${gatewayOnline ? 'topbar__btn--connected' : 'topbar__btn--disconnected'}`}
              aria-label={gatewayOnline ? 'Connected' : 'Disconnected'}
              title={gatewayOnline ? 'Gateway connected' : 'Gateway disconnected'}
            >
              {'\u25CF'}
            </span>

            {actor && (
              <span className="topbar__actor" title={actor}>
                <span className="topbar__actor-mark" aria-hidden="true">{actor.slice(0, 1).toUpperCase()}</span>
                {actor}
              </span>
            )}

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

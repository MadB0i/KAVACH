import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleUserRound,
  FileCheck2,
  FileClock,
  HeartPulse,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  PanelLeftClose,
  Search,
  Settings2,
  ShieldCheck,
  Sun,
  TerminalSquare,
  X,
} from 'lucide-react';
import { getHealth, verifyAudit } from '../api';
import { useAuth } from '../context/useAuth';
import { useTheme } from '../context/useTheme';
import { healthStateFrom, type HealthState } from '../utils/presentation';
import HealthIndicator from './HealthIndicator';

const navGroups = [
  {
    label: 'Command',
    items: [
      { to: '/', label: 'Overview', icon: LayoutDashboard },
      { to: '/live-requests', label: 'Live Requests', icon: Activity },
      { to: '/approvals', label: 'Pending Approvals', icon: FileClock },
    ],
  },
  {
    label: 'Assurance',
    items: [
      { to: '/audit', label: 'Audit Timeline', icon: TerminalSquare },
      { to: '/audit-verify', label: 'Audit Verification', icon: FileCheck2 },
      { to: '/policies', label: 'Policies', icon: ShieldCheck },
      { to: '/warnings', label: 'Security Warnings', icon: AlertTriangle },
    ],
  },
  {
    label: 'Runtime',
    items: [
      { to: '/agents', label: 'Agents / Sessions', icon: Bot },
      { to: '/health', label: 'System Health', icon: HeartPulse },
      { to: '/config', label: 'Configuration', icon: Settings2 },
    ],
  },
];

const routeTitles = new Map(navGroups.flatMap((group) => group.items.map((item) => [item.to, item.label])));

export default function Layout() {
  const { actor, logout } = useAuth();
  const { toggleTheme, isDark } = useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [operatorOpen, setOperatorOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [gatewayState, setGatewayState] = useState<HealthState>('loading');
  const [auditState, setAuditState] = useState<HealthState>('loading');
  const navigate = useNavigate();
  const location = useLocation();
  const operatorRef = useRef<HTMLDivElement>(null);

  const title = useMemo(() => routeTitles.get(location.pathname) || 'KAVACH', [location.pathname]);

  const refreshShellStatus = useCallback(async () => {
    try {
      const health = await getHealth();
      setGatewayState(healthStateFrom(health?.status));
    } catch {
      setGatewayState('error');
    }
    try {
      const audit = await verifyAudit();
      setAuditState(audit.chain_valid ? 'healthy' : 'error');
    } catch {
      setAuditState('unavailable');
    }
  }, []);

  useEffect(() => {
    refreshShellStatus();
    const interval = window.setInterval(refreshShellStatus, 30000);
    return () => window.clearInterval(interval);
  }, [refreshShellStatus]);

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
  }, [location.pathname]);

  useEffect(() => {
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOperatorOpen(false);
        setSidebarOpen(false);
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        document.getElementById('global-search')?.focus();
      }
    };
    document.addEventListener('keydown', handleKey);
    return () => document.removeEventListener('keydown', handleKey);
  }, []);

  useEffect(() => {
    const handlePointer = (event: MouseEvent) => {
      if (operatorRef.current && !operatorRef.current.contains(event.target as Node)) {
        setOperatorOpen(false);
      }
    };
    document.addEventListener('mousedown', handlePointer);
    return () => document.removeEventListener('mousedown', handlePointer);
  }, []);

  const handleLogout = useCallback(() => {
    logout();
    navigate('/login');
  }, [logout, navigate]);

  const handleSearch = (event: FormEvent) => {
    event.preventDefault();
    const value = query.trim();
    navigate(value ? `/audit?request_id=${encodeURIComponent(value)}` : '/audit');
  };

  return (
    <div className="app-layout">
      <aside
        className={`sidebar ${sidebarOpen ? 'sidebar--open' : ''} ${collapsed ? 'sidebar--collapsed' : ''}`}
        aria-label="Primary navigation"
      >
        <div className="sidebar__brand">
          <div className="sidebar__logo" aria-hidden="true">
            <ShieldCheck size={21} strokeWidth={1.8} />
          </div>
          <div className="sidebar__brand-text">
            <div className="sidebar__brand-name">KAVACH</div>
            <div className="sidebar__brand-sub">Zero-Trust Control Plane</div>
          </div>
          <button
            type="button"
            className="sidebar__mobile-close"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>

        <div className="sidebar__environment">
          <span className="sidebar__environment-mark" aria-hidden="true" />
          <span className="sidebar__label">
            <strong>Local Runtime</strong>
            <small>Protected workspace</small>
          </span>
        </div>

        <nav className="sidebar__nav-wrap">
          {navGroups.map((group) => (
            <div className="sidebar__group" key={group.label}>
              <div className="sidebar__section-label">{group.label}</div>
              <ul className="sidebar__nav">
                {group.items.map(({ to, label, icon: Icon }) => (
                  <li key={to}>
                    <NavLink
                      to={to}
                      end={to === '/'}
                      className={({ isActive }) => `sidebar__link ${isActive ? 'sidebar__link--active' : ''}`}
                      onClick={() => setSidebarOpen(false)}
                      aria-label={label}
                      title={collapsed ? label : undefined}
                    >
                      <span className="sidebar__icon" aria-hidden="true"><Icon size={17} strokeWidth={1.8} /></span>
                      <span className="sidebar__label">{label}</span>
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <div className="sidebar__footer">
          <div className="sidebar__assurance">
            <ShieldCheck size={16} aria-hidden="true" />
            <span className="sidebar__label">
              <strong>Fail closed</strong>
              <small>Enforcement active</small>
            </span>
          </div>
          <button
            type="button"
            className="sidebar__collapse-btn"
            onClick={() => setCollapsed((value) => !value)}
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? <ChevronRight size={17} /> : <PanelLeftClose size={17} />}
            <span className="sidebar__label">Collapse panel</span>
          </button>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div className="topbar__left">
            <button
              className="topbar__mobile-menu"
              type="button"
              onClick={() => setSidebarOpen((value) => !value)}
              aria-label={sidebarOpen ? 'Close navigation' : 'Open navigation'}
              aria-expanded={sidebarOpen}
            >
              {sidebarOpen ? <X size={19} /> : <Menu size={19} />}
            </button>
            <div className="topbar__context">
              <span>Control plane</span>
              <ChevronRight size={12} aria-hidden="true" />
              <strong>{title}</strong>
            </div>
          </div>

          <form className="topbar__search" role="search" onSubmit={handleSearch}>
            <Search size={15} strokeWidth={1.8} aria-hidden="true" />
            <input
              id="global-search"
              className="topbar__search-input"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search request correlation…"
              aria-label="Search audit events by request ID"
            />
            <kbd>Ctrl K</kbd>
          </form>

          <div className="topbar__right">
            <div className="topbar__signals" aria-label="Runtime status">
              <HealthIndicator state={gatewayState} label="Gateway" compact />
              <HealthIndicator state={auditState} label="Audit" compact />
            </div>
            <button
              className="topbar__icon-button"
              type="button"
              onClick={toggleTheme}
              aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
              title={isDark ? 'Light mode' : 'Dark mode'}
            >
              {isDark ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <div className="operator-menu" ref={operatorRef}>
              <button
                className="operator-menu__trigger"
                type="button"
                onClick={() => setOperatorOpen((value) => !value)}
                aria-label="Open operator menu"
                aria-expanded={operatorOpen}
              >
                <span className="operator-menu__avatar"><CircleUserRound size={18} /></span>
                <span className="operator-menu__identity">
                  <strong>{actor || 'Operator'}</strong>
                  <small>Authenticated</small>
                </span>
                <ChevronLeft className={operatorOpen ? 'operator-menu__chevron--open' : ''} size={14} />
              </button>
              {operatorOpen && (
                <div className="operator-menu__popover" role="menu">
                  <div className="operator-menu__summary">
                    <CheckCircle2 size={15} />
                    <span>Session token held in memory</span>
                  </div>
                  <button type="button" role="menuitem" onClick={handleLogout}>
                    <LogOut size={15} />
                    End session
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="content" id="main-content">
          <Outlet />
        </main>
      </div>

      {sidebarOpen && (
        <button
          type="button"
          className="sidebar-overlay"
          onClick={() => setSidebarOpen(false)}
          aria-label="Close navigation"
        />
      )}
    </div>
  );
}

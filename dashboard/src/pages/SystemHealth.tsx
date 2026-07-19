import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  Boxes,
  CheckCircle2,
  Clock3,
  Database,
  FileCheck2,
  GitBranch,
  HardDrive,
  HeartPulse,
  Network,
  RefreshCw,
  Server,
  ShieldCheck,
  TerminalSquare,
} from 'lucide-react';
import { getHealth, getReady, getStatus } from '../api';
import type { HealthStatus, ReadyStatus, StatusInfo } from '../types';
import HealthIndicator from '../components/HealthIndicator';
import LoadingSkeleton from '../components/LoadingSkeleton';
import PageHeader from '../components/PageHeader';
import SectionCard from '../components/SectionCard';
import { healthStateFrom, type HealthState } from '../utils/presentation';

interface Probe<T> {
  data: T | null;
  latency: number | null;
  state: HealthState;
}

async function measure<T>(request: Promise<T>): Promise<{ data: T; latency: number }> {
  const start = window.performance.now();
  const data = await request;
  return { data, latency: Math.max(1, Math.round(window.performance.now() - start)) };
}

function formatUptime(seconds?: number): string {
  if (seconds === undefined) return 'Unavailable';
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return [days ? `${days}d` : '', hours ? `${hours}h` : '', `${minutes}m`].filter(Boolean).join(' ');
}

export default function SystemHealth() {
  const [healthProbe, setHealthProbe] = useState<Probe<HealthStatus>>({ data: null, latency: null, state: 'loading' });
  const [readyProbe, setReadyProbe] = useState<Probe<ReadyStatus>>({ data: null, latency: null, state: 'loading' });
  const [statusProbe, setStatusProbe] = useState<Probe<StatusInfo>>({ data: null, latency: null, state: 'loading' });
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchAll = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    const [healthResult, readyResult, statusResult] = await Promise.allSettled([
      measure(getHealth()),
      measure(getReady()),
      measure(getStatus()),
    ]);

    setHealthProbe(healthResult.status === 'fulfilled'
      ? { ...healthResult.value, state: healthStateFrom(healthResult.value.data.status) }
      : { data: null, latency: null, state: 'error' });
    setReadyProbe(readyResult.status === 'fulfilled'
      ? {
        ...readyResult.value,
        state: healthStateFrom(readyResult.value.data.ready ?? readyResult.value.data.status),
      }
      : { data: null, latency: null, state: 'error' });
    setStatusProbe(statusResult.status === 'fulfilled'
      ? { ...statusResult.value, state: 'healthy' }
      : { data: null, latency: null, state: 'error' });
    setLastRefresh(new Date());
    setRefreshing(false);
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = window.setInterval(() => fetchAll(), 15000);
    return () => window.clearInterval(interval);
  }, [fetchAll]);

  const components = useMemo(() => {
    const health = healthProbe.data;
    const ready = readyProbe.data;
    return [
      { name: 'Gateway API', icon: Server, state: healthStateFrom(health?.status), source: '/health', latency: healthProbe.latency, note: 'Ingress and authentication boundary' },
      { name: 'Policy engine', icon: ShieldCheck, state: healthStateFrom(ready?.policy_loaded ?? health?.policy_engine), source: '/ready', latency: readyProbe.latency, note: 'Default-deny decision engine' },
      { name: 'Audit store', icon: FileCheck2, state: healthStateFrom(ready?.audit_available ?? health?.audit_store), source: '/ready', latency: readyProbe.latency, note: 'Hash-linked event ledger' },
      { name: 'Approval store', icon: Database, state: healthStateFrom(ready?.approval_available ?? health?.approval_store), source: '/ready', latency: readyProbe.latency, note: 'Human authorization state' },
      { name: 'Filesystem adapter', icon: HardDrive, state: healthStateFrom(ready?.adapter_filesystem ?? ready?.adapters?.filesystem), source: '/ready', latency: readyProbe.latency, note: 'Workspace containment' },
      { name: 'Command adapter', icon: TerminalSquare, state: healthStateFrom(ready?.adapter_command ?? ready?.adapters?.command), source: '/ready', latency: readyProbe.latency, note: 'Executable enforcement' },
      { name: 'Network adapter', icon: Network, state: healthStateFrom(ready?.adapter_network ?? ready?.adapters?.network), source: '/ready', latency: readyProbe.latency, note: 'SSRF and redirect controls' },
    ];
  }, [healthProbe, readyProbe]);

  const observable = components.filter((component) => component.state !== 'unavailable');
  const healthy = observable.filter((component) => component.state === 'healthy').length;
  const score = observable.length ? Math.round((healthy / observable.length) * 100) : null;
  const overall: HealthState = [healthProbe.state, readyProbe.state, statusProbe.state].some((state) => state === 'error')
    ? 'error'
    : [healthProbe.state, readyProbe.state, statusProbe.state].some((state) => state === 'loading')
      ? 'loading'
      : observable.some((component) => component.state === 'warning' || component.state === 'unavailable')
        ? 'warning'
        : 'healthy';
  const uptime = statusProbe.data?.uptime_seconds ?? statusProbe.data?.uptime;

  return (
    <div className="page health-page">
      <PageHeader
        eyebrow="Runtime assurance"
        title="System Health"
        icon={HeartPulse}
        subtitle="Dependency readiness and locally observed gateway response time."
        actions={
          <div className="page-refresh">
            <span>{lastRefresh ? `Updated ${lastRefresh.toLocaleTimeString()}` : 'First probe running'}</span>
            <button className="btn btn--secondary btn--sm" type="button" onClick={() => fetchAll(true)} disabled={refreshing}>
              <RefreshCw className={refreshing ? 'spin' : ''} size={14} />
              Refresh
            </button>
          </div>
        }
      />

      <section className={`health-hero health-hero--${overall}`}>
        <div className="health-hero__score">
          <span>{score === null ? '?' : score}</span>
          <small>{score === null ? 'unknown' : '/ 100'}</small>
        </div>
        <div className="health-hero__body">
          <span className="health-hero__eyebrow">Observed health score</span>
          <h2>{overall === 'healthy' ? 'All observable dependencies ready' : overall === 'loading' ? 'Probing runtime dependencies' : overall === 'error' ? 'Runtime dependency failure' : 'Partial health information'}</h2>
          <p>{observable.length ? `${healthy} of ${observable.length} reported components are healthy.` : 'No component readiness details are currently available.'}</p>
          <div className="health-hero__badges">
            <HealthIndicator state={healthProbe.state} label="Health probe" compact />
            <HealthIndicator state={readyProbe.state} label="Readiness probe" compact />
            <HealthIndicator state={statusProbe.state} label="Status API" compact />
          </div>
        </div>
        <div className="health-hero__runtime">
          <div><span>Service</span><strong>{statusProbe.data?.service || 'Unavailable'}</strong></div>
          <div><span>Version</span><strong>{statusProbe.data?.version ? `v${statusProbe.data.version}` : 'Unavailable'}</strong></div>
          <div><span>Bind</span><strong>{statusProbe.data?.bind || statusProbe.data?.bind_address || 'Unavailable'}</strong></div>
          <div><span>Uptime</span><strong>{formatUptime(uptime)}</strong></div>
        </div>
      </section>

      <SectionCard
        title="Runtime components"
        actions={<span className="section-card__meta">{components.length} dependency signals</span>}
      >
        {overall === 'loading' ? (
          <LoadingSkeleton type="card" count={4} />
        ) : (
          <div className="health-component-grid">
            {components.map(({ name, icon: Icon, state, source, latency, note }) => (
              <article className={`health-component health-component--${state}`} key={name}>
                <div className="health-component__top">
                  <span className="health-component__icon"><Icon size={17} strokeWidth={1.8} /></span>
                  <HealthIndicator state={state} compact />
                </div>
                <h3>{name}</h3>
                <p>{note}</p>
                <div className="health-component__meta">
                  <span><Activity size={12} />{latency !== null ? `${latency} ms client RTT` : 'Latency unavailable'}</span>
                  <span><GitBranch size={12} />{source}</span>
                </div>
              </article>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard title="Dependency relationship">
        <div className="dependency-map" role="img" aria-label="Gateway dependencies flow from request ingress through the policy engine to approval, audit, and enforcement adapters">
          <div className="dependency-node dependency-node--primary">
            <Server size={18} />
            <span><strong>Gateway</strong><small>Authenticated ingress</small></span>
          </div>
          <span className="dependency-map__connector" aria-hidden="true"><GitBranch size={16} /></span>
          <div className="dependency-map__cluster">
            <div className="dependency-node"><ShieldCheck size={17} /><span><strong>Policy</strong><small>Decision</small></span></div>
            <div className="dependency-node"><Database size={17} /><span><strong>Approvals</strong><small>Human gate</small></span></div>
            <div className="dependency-node"><FileCheck2 size={17} /><span><strong>Audit</strong><small>Evidence</small></span></div>
          </div>
          <span className="dependency-map__connector" aria-hidden="true"><GitBranch size={16} /></span>
          <div className="dependency-map__cluster">
            <div className="dependency-node"><HardDrive size={17} /><span><strong>Filesystem</strong><small>Adapter</small></span></div>
            <div className="dependency-node"><TerminalSquare size={17} /><span><strong>Command</strong><small>Adapter</small></span></div>
            <div className="dependency-node"><Network size={17} /><span><strong>Network</strong><small>Adapter</small></span></div>
          </div>
        </div>
        <div className="dependency-footnote">
          <Boxes size={14} />
          Readiness is reported by the gateway. Response times are measured locally in this browser and are not server-side latency metrics.
          {overall === 'healthy' && <span><CheckCircle2 size={13} /> Dependency path ready</span>}
        </div>
      </SectionCard>

      <div className="health-probe-strip">
        {[
          { label: '/health', probe: healthProbe },
          { label: '/ready', probe: readyProbe },
          { label: '/api/status', probe: statusProbe },
        ].map(({ label, probe }) => (
          <div key={label}>
            <Clock3 size={14} />
            <span><strong>{label}</strong>{probe.latency !== null ? `${probe.latency} ms` : 'No response'}</span>
            <HealthIndicator state={probe.state} compact />
          </div>
        ))}
      </div>
    </div>
  );
}

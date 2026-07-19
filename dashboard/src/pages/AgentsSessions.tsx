import { useEffect, useState, useCallback } from 'react';
import { getAuditEvents } from '../api';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

interface AgentInfo {
  agent_id: string;
  last_activity: string;
  total_requests: number;
}

export default function AgentsSessions() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    try {
      const events = await getAuditEvents({ limit: 200 });
      const agentMap = new Map<string, { last: string; count: number }>();
      for (const ev of events) {
        if (ev.agent_id) {
          if (!agentMap.has(ev.agent_id)) {
            agentMap.set(ev.agent_id, { last: '', count: 0 });
          }
          const entry = agentMap.get(ev.agent_id)!;
          entry.count++;
          if (ev.timestamp && (!entry.last || ev.timestamp > entry.last)) {
            entry.last = ev.timestamp;
          }
        }
      }
      const result: AgentInfo[] = Array.from(agentMap.entries()).map(([id, info]) => ({
        agent_id: id,
        last_activity: info.last || 'Unknown',
        total_requests: info.count,
      }));
      result.sort((a, b) => b.total_requests - a.total_requests);
      setAgents(result);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load agents');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, [fetchAgents]);

  if (loading) return <LoadingState message="Loading agent data..." />;
  if (error) return <ErrorState title="Failed to load agents" message={error} onRetry={fetchAgents} />;

  return (
    <div className="page">
      <PageHeader
        title="Agents"
        subtitle="Agent activity derived from audit events"
      />

      {agents.length === 0 ? (
        <EmptyState
          icon={'\u25CB'}
          title="No Agents Found"
          description="No agent activity has been recorded in recent audit events."
        />
      ) : (
        <DataTable
          columns={[
            { key: 'agent_id', header: 'Agent ID', className: 'cell-mono', render: (a) => a.agent_id },
            { key: 'requests', header: 'Requests', render: (a) => a.total_requests },
            { key: 'last', header: 'Last Activity', render: (a) => a.last_activity ? new Date(a.last_activity).toLocaleString() : 'Unknown' },
          ]}
          data={agents}
          keyField={(a) => a.agent_id}
          emptyTitle="No Agents Found"
          emptyDescription="No agent activity recorded in recent audit events."
        />
      )}
    </div>
  );
}

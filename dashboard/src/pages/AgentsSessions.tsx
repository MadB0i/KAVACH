import { useEffect, useState, useCallback } from 'react';
import { getAuditEvents } from '../api';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';

interface AgentInfo {
  agent_id: string;
  session_count: number;
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
      const agentMap = new Map<string, { sessions: Set<string>; last: string; count: number }>();
      for (const ev of events) {
        if (ev.agent_id) {
          if (!agentMap.has(ev.agent_id)) {
            agentMap.set(ev.agent_id, { sessions: new Set(), last: '', count: 0 });
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
        session_count: info.sessions.size || 1,
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
      <h2 className="page__title">Agents & Sessions</h2>
      <p className="page__subtitle">Agent activity derived from audit events</p>

      {agents.length === 0 ? (
        <EmptyState icon={'\u263C'} title="No Agents Found" description="No agent activity has been recorded in recent audit events." />
      ) : (
        <div className="table-container">
          <table className="table" role="table">
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Total Requests</th>
                <th>Last Activity</th>
              </tr>
            </thead>
            <tbody>
              {agents.map((agent) => (
                <tr key={agent.agent_id}>
                  <td className="cell-mono">{agent.agent_id}</td>
                  <td>{agent.total_requests}</td>
                  <td>{agent.last_activity ? new Date(agent.last_activity).toLocaleString() : 'Unknown'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

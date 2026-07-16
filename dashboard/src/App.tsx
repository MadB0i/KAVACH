import { Routes, Route, Navigate } from 'react-router-dom';
import ProtectedRoute from './components/ProtectedRoute';
import Layout from './components/Layout';
import Login from './pages/Login';
import Overview from './pages/Overview';
import LiveRequests from './pages/LiveRequests';
import PendingApprovals from './pages/PendingApprovals';
import AuditTimeline from './pages/AuditTimeline';
import Policies from './pages/Policies';
import AgentsSessions from './pages/AgentsSessions';
import SecurityWarnings from './pages/SecurityWarnings';
import SystemHealth from './pages/SystemHealth';
import ConfigSummary from './pages/ConfigSummary';
import AuditVerification from './pages/AuditVerification';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route path="/" element={<Overview />} />
          <Route path="/live-requests" element={<LiveRequests />} />
          <Route path="/approvals" element={<PendingApprovals />} />
          <Route path="/audit" element={<AuditTimeline />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/agents" element={<AgentsSessions />} />
          <Route path="/warnings" element={<SecurityWarnings />} />
          <Route path="/health" element={<SystemHealth />} />
          <Route path="/config" element={<ConfigSummary />} />
          <Route path="/audit-verify" element={<AuditVerification />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

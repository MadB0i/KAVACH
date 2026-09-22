import { AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';
import type { RiskLevel } from '../utils/presentation';

interface RiskBadgeProps {
  level: RiskLevel;
  label?: string;
}

export default function RiskBadge({ level, label }: RiskBadgeProps) {
  const Icon = level === 'high' ? ShieldAlert : level === 'medium' ? AlertTriangle : ShieldCheck;
  return (
    <span className={`risk-badge risk-badge--${level}`}>
      <Icon size={12} strokeWidth={2} aria-hidden="true" />
      {label || `${level} risk`}
    </span>
  );
}

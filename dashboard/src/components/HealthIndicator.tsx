import { CircleAlert, CircleCheck, CircleHelp, CircleX, LoaderCircle } from 'lucide-react';
import type { HealthState } from '../utils/presentation';

interface HealthIndicatorProps {
  state: HealthState;
  label?: string;
  compact?: boolean;
}

const stateMeta = {
  healthy: { Icon: CircleCheck, label: 'Healthy' },
  warning: { Icon: CircleAlert, label: 'Warning' },
  error: { Icon: CircleX, label: 'Error' },
  unavailable: { Icon: CircleHelp, label: 'Unavailable' },
  loading: { Icon: LoaderCircle, label: 'Checking' },
};

export default function HealthIndicator({ state, label, compact = false }: HealthIndicatorProps) {
  const { Icon, label: defaultLabel } = stateMeta[state];
  return (
    <span className={`health-indicator health-indicator--${state} ${compact ? 'health-indicator--compact' : ''}`}>
      <Icon className={state === 'loading' ? 'spin' : ''} size={compact ? 13 : 15} strokeWidth={2} aria-hidden="true" />
      <span>{label || defaultLabel}</span>
    </span>
  );
}

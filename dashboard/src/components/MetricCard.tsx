import LoadingState from './LoadingState';
import ErrorState from './ErrorState';
import StatusBadge from './StatusBadge';

interface MetricCardProps {
  label: string;
  value: string | number;
  icon?: string;
  variant?: 'success' | 'warning' | 'error' | 'info';
  loading?: boolean;
  error?: string | null;
  subtitle?: string;
  onClick?: () => void;
}

export default function MetricCard({
  label,
  value,
  icon,
  variant,
  loading = false,
  error = null,
  subtitle,
  onClick,
}: MetricCardProps) {
  return (
    <div
      className={`metric-card ${onClick ? 'metric-card--clickable' : ''}`}
      onClick={onClick}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter') onClick(); } : undefined}
    >
      <div className="metric-card__top">
        <span className="metric-card__label">{label}</span>
        {icon && <span className="metric-card__icon">{icon}</span>}
      </div>
      {loading ? (
        <LoadingState compact />
      ) : error ? (
        <ErrorState title="Error" message={error} compact />
      ) : (
        <>
          <div className="metric-card__value">
            {variant ? <StatusBadge variant={variant} label={String(value)} /> : value}
          </div>
          {subtitle && <div className="metric-card__sub">{subtitle}</div>}
        </>
      )}
    </div>
  );
}

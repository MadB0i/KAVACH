import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

export type MetricTone = 'default' | 'accent' | 'success' | 'warning' | 'danger';

interface SecurityMetricCardProps {
  label: string;
  value: ReactNode;
  detail: string;
  icon: LucideIcon;
  tone?: MetricTone;
  loading?: boolean;
}

export default function SecurityMetricCard({
  label,
  value,
  detail,
  icon: Icon,
  tone = 'default',
  loading = false,
}: SecurityMetricCardProps) {
  return (
    <article className={`security-metric security-metric--${tone}`}>
      <div className="security-metric__icon" aria-hidden="true">
        <Icon size={17} strokeWidth={1.8} />
      </div>
      <div className="security-metric__content">
        <span className="security-metric__label">{label}</span>
        {loading ? (
          <span className="security-metric__loading" aria-label={`Loading ${label}`} />
        ) : (
          <strong className="security-metric__value">{value}</strong>
        )}
        <span className="security-metric__detail">{detail}</span>
      </div>
    </article>
  );
}

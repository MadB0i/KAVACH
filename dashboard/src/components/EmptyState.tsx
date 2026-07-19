import { ShieldQuestion, type LucideIcon } from 'lucide-react';
import { createElement } from 'react';
import type { ReactNode } from 'react';

interface EmptyStateProps {
  icon?: string | LucideIcon;
  title: string;
  description: string;
  action?: ReactNode;
  compact?: boolean;
}

export default function EmptyState({
  icon: iconValue = ShieldQuestion,
  title,
  description,
  action,
  compact = false,
}: EmptyStateProps) {
  const iconNode = typeof iconValue === 'string'
    ? iconValue
    : createElement(iconValue, { size: 22, strokeWidth: 1.7 });
  return (
    <div className={`empty-state ${compact ? 'empty-state--compact' : ''}`}>
      <div className="empty-state__icon" aria-hidden="true">
        {iconNode}
      </div>
      <h3 className="empty-state__title">{title}</h3>
      <p className="empty-state__description">{description}</p>
      {action && <div className="empty-state__action">{action}</div>}
    </div>
  );
}

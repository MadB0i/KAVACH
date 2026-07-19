import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  eyebrow?: string;
  icon?: LucideIcon;
}

export default function PageHeader({ title, subtitle, actions, eyebrow, icon: Icon }: PageHeaderProps) {
  return (
    <div className="page__header">
      <div className="page__header-left">
        {eyebrow && <span className="page__eyebrow">{eyebrow}</span>}
        <h2>{Icon && <Icon size={20} strokeWidth={1.8} aria-hidden="true" />}{title}</h2>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="page__actions">{actions}</div>}
    </div>
  );
}

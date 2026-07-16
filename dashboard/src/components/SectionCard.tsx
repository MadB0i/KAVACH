import type { ReactNode } from 'react';

interface SectionCardProps {
  title: string;
  actions?: ReactNode;
  flush?: boolean;
  children: ReactNode;
}

export default function SectionCard({ title, actions, flush = false, children }: SectionCardProps) {
  return (
    <section className="section-card">
      <div className="section-card__header">
        <h3 className="section-card__title">{title}</h3>
        {actions && <div className="page__actions">{actions}</div>}
      </div>
      <div className={`section-card__body ${flush ? 'section-card__body--flush' : ''}`}>
        {children}
      </div>
    </section>
  );
}

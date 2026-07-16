interface EmptyStateProps {
  icon?: string;
  title: string;
  description: string;
}

export default function EmptyState({ icon = '\u2139', title, description }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <span className="empty-state__icon" aria-hidden="true">{icon}</span>
      <h3 className="empty-state__title">{title}</h3>
      <p className="empty-state__description">{description}</p>
    </div>
  );
}

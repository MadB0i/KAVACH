interface StatusBadgeProps {
  variant: 'success' | 'warning' | 'error' | 'info' | 'pending';
  label: string;
  dot?: boolean;
}

export default function StatusBadge({ variant, label, dot = true }: StatusBadgeProps) {
  return (
    <span className={`badge badge--${variant}`} role="status" aria-label={label}>
      {dot && <span className="badge__dot" aria-hidden="true" />}
      <span>{label}</span>
    </span>
  );
}

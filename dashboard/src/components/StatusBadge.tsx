interface StatusBadgeProps {
  variant: 'success' | 'warning' | 'error' | 'info' | 'pending';
  label: string;
}

const variantIcons: Record<string, string> = {
  success: '\u2713',
  warning: '\u26A0',
  error: '\u2717',
  info: '\u2139',
  pending: '\u23F3',
};

export default function StatusBadge({ variant, label }: StatusBadgeProps) {
  return (
    <span className={`badge badge--${variant}`} role="status" aria-label={`${variant}: ${label}`}>
      <span className="badge__icon" aria-hidden="true">{variantIcons[variant] || ''}</span>
      <span className="badge__label">{label}</span>
    </span>
  );
}

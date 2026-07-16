interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
  compact?: boolean;
}

export default function ErrorState({ title = 'Error', message, onRetry, compact = false }: ErrorStateProps) {
  if (compact) {
    return (
      <div className="error-state" role="alert" style={{ padding: '8px 0', gap: 4 }}>
        <p className="error-state__message" style={{ fontSize: '0.75rem', marginBottom: 0 }}>{message}</p>
      </div>
    );
  }

  return (
    <div className="error-state" role="alert">
      <div className="error-state__icon">{'\u26A0'}</div>
      <h3 className="error-state__title">{title}</h3>
      <p className="error-state__message">{message}</p>
      {onRetry && (
        <button className="btn btn--primary" onClick={onRetry} aria-label="Retry">
          Retry
        </button>
      )}
    </div>
  );
}

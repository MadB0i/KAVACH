interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export default function ErrorState({ title = 'Error', message, onRetry }: ErrorStateProps) {
  return (
    <div className="error-state" role="alert">
      <span className="error-state__icon" aria-hidden="true">{'\u26A0'}</span>
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

interface LoadingStateProps {
  message?: string;
  compact?: boolean;
}

export default function LoadingState({ message = 'Loading...', compact = false }: LoadingStateProps) {
  if (compact) {
    return (
      <div className="loading-state loading-state--compact" role="status" aria-label="Loading">
        <div className="spinner spinner--sm" aria-hidden="true" />
      </div>
    );
  }

  return (
    <div className="loading-state" role="status" aria-label={message}>
      <div className="spinner" aria-hidden="true" />
      <p className="loading-state__message">{message}</p>
    </div>
  );
}

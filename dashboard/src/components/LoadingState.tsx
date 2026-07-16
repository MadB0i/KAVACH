interface LoadingStateProps {
  message?: string;
  compact?: boolean;
}

export default function LoadingState({ message = 'Loading...', compact = false }: LoadingStateProps) {
  return (
    <div className={`loading-state ${compact ? 'loading-state--compact' : ''}`} role="status" aria-label={message}>
      <div className="spinner" aria-hidden="true" />
      <p className="loading-state__message">{message}</p>
    </div>
  );
}

interface LoadingSkeletonProps {
  type?: 'text' | 'title' | 'card' | 'row';
  count?: number;
}

export default function LoadingSkeleton({ type = 'text', count = 3 }: LoadingSkeletonProps) {
  const className = `skeleton skeleton--${type}`;

  if (type === 'row' || type === 'text') {
    return (
      <div>
        {Array.from({ length: count }).map((_, i) => (
          <div key={i} className={className} style={type === 'text' ? { marginBottom: 10 } : {}} />
        ))}
      </div>
    );
  }

  if (type === 'title') {
    return <div className={className} />;
  }

  if (type === 'card') {
    return (
      <div style={{ display: 'grid', gridTemplateColumns: `repeat(${count}, 1fr)`, gap: 12 }}>
        {Array.from({ length: count }).map((_, i) => (
          <div key={i} className={className} />
        ))}
      </div>
    );
  }

  return null;
}

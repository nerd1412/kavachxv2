import React from 'react';

export function Skeleton({ className = '', style = {} }) {
  return <div className={`skeleton ${className}`} style={style} />;
}

export function SkeletonText({ lines = 3, className = '' }) {
  return (
    <div className={className}>
      {[...Array(lines)].map((_, i) => (
        <Skeleton key={i} className="skeleton-text" style={{ width: i === lines - 1 ? '70%' : '100%' }} />
      ))}
    </div>
  );
}

export function SkeletonCard({ hasIcon = true }) {
  return (
    <div className="card" style={{ padding: 20 }}>
      <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
        {hasIcon && <Skeleton className="skeleton-circle" />}
        <div style={{ flex: 1 }}>
          <Skeleton className="skeleton-title" style={{ height: 12, marginBottom: 8 }} />
          <Skeleton className="skeleton-text" style={{ width: '40%', height: 10 }} />
        </div>
      </div>
      <SkeletonText lines={2} />
    </div>
  );
}

export function SkeletonStat() {
  return (
    <div className="stat-card" style={{ '--stat-bg': 'var(--bg-elevated)', minHeight: 110 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Skeleton className="skeleton-circle" style={{ width: 24, height: 24 }} />
        <Skeleton className="skeleton-text" style={{ width: 40, height: 14 }} />
      </div>
      <Skeleton className="skeleton-title" style={{ height: 28, width: '60%', marginBottom: 10 }} />
      <Skeleton className="skeleton-text" style={{ width: '40%', height: 12 }} />
    </div>
  );
}

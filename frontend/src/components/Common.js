import React from 'react';
import '../styles/Common.css';

export function Card({ title, subtitle, children, className = '' }) {
  return (
    <div className={`card ${className}`}>
      {(title || subtitle) && (
        <div className="card-header">
          <div>
            {title && <div className="card-title">{title}</div>}
            {subtitle && <div className="card-subtitle">{subtitle}</div>}
          </div>
        </div>
      )}
      <div className="card-content">
        {children}
      </div>
    </div>
  );
}

export function Button({ variant = 'primary', size = 'md', children, ...props }) {
  const classes = `btn btn-${variant} btn-${size}`;
  return <button className={classes} {...props}>{children}</button>;
}

export function Alert({ type = 'info', children }) {
  return (
    <div className={`alert alert-${type}`}>
      <span className="alert-icon">ℹ️</span>
      <span>{children}</span>
    </div>
  );
}

export function StatCard({ label, value, subtitle, className = '' }) {
  return (
    <div className={`stat-card ${className}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {subtitle && <div className="stat-subtitle">{subtitle}</div>}
    </div>
  );
}

export function Grid({ cols = 2, children, className = '' }) {
  return (
    <div className={`grid grid-${cols} ${className}`}>
      {children}
    </div>
  );
}

export function Section({ title, children, className = '' }) {
  return (
    <div className={`section ${className}`}>
      {title && <div className="section-title">{title}</div>}
      {children}
    </div>
  );
}

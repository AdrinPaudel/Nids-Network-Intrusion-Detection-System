import { useState, useEffect } from 'react';
import { Card, Alert, StatCard, Grid, Section } from '../components/Common';
import axios from 'axios';
import '../styles/Dashboard.css';

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

function formatPct(value) {
  if (value == null) return 'N/A';
  const pct = value <= 1 ? (value * 100).toFixed(1) : Number(value).toFixed(1);
  return `${pct}%`;
}

function formatF1(value) {
  if (value == null) return 'N/A';
  return value <= 1 ? Number(value).toFixed(3) : Number(value).toFixed(1);
}

function formatDate(iso) {
  if (!iso) return 'N/A';
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  } catch {
    return 'N/A';
  }
}

function formatUptime(seconds) {
  if (!seconds || seconds <= 0) return 'N/A';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// ---------------------------------------------------------------------------
// Static model card data (values from training_metadata.json).
// The default model's accuracy/F1 are overridden by live API values when
// available; the "all" model card always uses these static values since
// dashboard-stats only reads the default model's metadata.
// ---------------------------------------------------------------------------

const MODEL_DEFAULTS = {
  default: {
    label: '5 Class (Default)',
    classes: 'Benign, DDoS, DoS, Brute Force, Botnet',
    features: 40,
    trainingDate: '2026-03-04',
    cvScore: 0.9993,
    f1Score: null,
  },
  all: {
    label: '6 Class (All)',
    classes: 'Benign, DDoS, DoS, Brute Force, Botnet, Infilteration',
    features: 40,
    trainingDate: '2026-03-04',
    cvScore: 0.8886,
    f1Score: null,
  },
};

// ---------------------------------------------------------------------------
// ModelCard component
// ---------------------------------------------------------------------------

function ModelCard({ label, accuracy, f1, features, trainingDate, classes }) {
  return (
    <div className="dashboard-model-card">
      <div className="dashboard-model-header">
        <span className="dashboard-model-label">{label}</span>
        <span className="dashboard-model-status">Ready</span>
      </div>
      <div className="dashboard-model-classes">{classes}</div>
      <Grid cols={2}>
        <StatCard label="Accuracy" value={accuracy} />
        <StatCard label="Macro F1" value={f1} />
        <StatCard label="Features" value={features} />
        <StatCard label="Trained" value={trainingDate} />
      </Grid>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard page
// ---------------------------------------------------------------------------

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    axios.get('/api/dashboard-stats')
      .then((res) => { if (!cancelled) setStats(res.data); })
      .catch(() => { if (!cancelled) setError('Could not load dashboard data.'); })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <Section title="NIDS — Network Intrusion Detection System">
        <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          Loading...
        </div>
      </Section>
    );
  }

  if (error) {
    return (
      <Section title="NIDS — Network Intrusion Detection System">
        <Alert type="danger">{error}</Alert>
      </Section>
    );
  }

  // Merge live API accuracy into the default model card; fall back to CV score.
  const defaultAccuracy = stats?.model_accuracy != null
    ? formatPct(stats.model_accuracy)
    : formatPct(MODEL_DEFAULTS.default.cvScore);

  const defaultF1 = stats?.f1_score != null
    ? formatF1(stats.f1_score)
    : formatF1(MODEL_DEFAULTS.default.cvScore);

  const defaultDate = stats?.last_training
    ? formatDate(stats.last_training)
    : MODEL_DEFAULTS.default.trainingDate;

  return (
    <Section title="NIDS — Network Intrusion Detection System">

      {/* Model status cards */}
      <div className="dashboard-models-grid">
        <ModelCard
          label={MODEL_DEFAULTS.default.label}
          accuracy={defaultAccuracy}
          f1={defaultF1}
          features={MODEL_DEFAULTS.default.features}
          trainingDate={defaultDate}
          classes={MODEL_DEFAULTS.default.classes}
        />
        <ModelCard
          label={MODEL_DEFAULTS.all.label}
          accuracy={formatPct(MODEL_DEFAULTS.all.cvScore)}
          f1={formatF1(MODEL_DEFAULTS.all.cvScore)}
          features={MODEL_DEFAULTS.all.features}
          trainingDate={MODEL_DEFAULTS.all.trainingDate}
          classes={MODEL_DEFAULTS.all.classes}
        />
      </div>

      {/* System info strip */}
      <Card title="System">
        <Grid cols={3}>
          <div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.25rem' }}>
              Datasets Available
            </div>
            <div style={{ fontWeight: '600', fontSize: '1.1rem' }}>
              {stats?.datasets_available ?? 0} files
              {stats?.datasets_size_gb > 0 ? ` (${stats.datasets_size_gb} GB)` : ''}
            </div>
          </div>
          <div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.25rem' }}>
              Backend Version
            </div>
            <div style={{ fontWeight: '600', fontSize: '1.1rem' }}>1.0.0</div>
          </div>
          <div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '0.25rem' }}>
              System Uptime
            </div>
            <div style={{ fontWeight: '600', fontSize: '1.1rem' }}>
              {formatUptime(stats?.uptime_seconds)}
            </div>
          </div>
        </Grid>
      </Card>

    </Section>
  );
}

export default Dashboard;
